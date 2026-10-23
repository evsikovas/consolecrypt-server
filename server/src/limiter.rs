// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Request limits shared by every replica (security audit S2, ADR-0201
//! amendment): token buckets in PostgreSQL, taken atomically by
//! `cc_rate_take` (migration 0013) with the database clock only, so N
//! replicas behind a load balancer allow exactly what one would.
//!
//! * A limit ([`Limit`]) has a main bucket (`_RATE`/`_BURST`) and optional
//!   hourly and daily ceilings; every non-zero part is one bucket. All buckets
//!   of one call are taken together or not at all.
//! * Refusal: `429 rate_limited` with `Retry-After` and `details.limit`. In
//!   `CC_RATE_LIMIT_MODE=observe` (the 0.2.2 default) the request goes
//!   through and only `cc_rate_limit_observed_total` counts it; sign-in
//!   limits always enforce.
//! * Per-account overrides (`account_limits`, `admin limits`) are cached for
//!   at most [`OVERRIDES_TTL`] per replica.
//! * `limit_exceeded` audit events: at most one per hour per account and
//!   limit (`rate_counters`), so an attack cannot inflate the audit log.
//!
//! Reads stay on the in-memory limiters of [`crate::ratelimit`].

use crate::audit::{AuditEvent, AuditType};
use crate::config::limits::{Limit, LimitSpec, QUOTA_OVERRIDE_KEYS};
use crate::config::{Config, RateLimitMode};
use crate::error::{spawn_in_request, AppError, AppResult};
use crate::state::AppState;
use cc_protocol::{DeviceId, UserId};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// How long a replica may use a cached per-account override.
pub const OVERRIDES_TTL: Duration = Duration::from_secs(30);
const AUDIT_EVERY: Duration = Duration::from_secs(3600);

/// What a bucket is keyed by.
#[derive(Debug, Clone, Copy)]
pub enum Key<'a> {
    Device(DeviceId),
    Account(UserId),
    /// Client address (IPv4, IPv6 /64); `None` = unknown address.
    Ip(Option<IpAddr>),
    /// Normalised (lower-case) e-mail input — never stored in clear.
    Email(&'a str),
    /// E-mail input and the client's /24 (IPv4) or /64 (IPv6) network.
    EmailNet(&'a str, Option<IpAddr>),
}

/// A bucket id derived from non-id input (addresses, e-mails).
fn hashed(kind: &str, value: &str) -> Uuid {
    let h = crate::crypto::sha256(format!("cc-rate-v1|{kind}|{value}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    Uuid::from_bytes(b)
}

impl Key<'_> {
    fn id(&self) -> Uuid {
        let net = |ip: Option<IpAddr>| {
            ip.map_or_else(
                || "unknown".to_owned(),
                |ip| crate::ratelimit::subnet_key(ip).to_string(),
            )
        };
        match *self {
            Key::Device(d) => d.into(),
            Key::Account(u) => u.into(),
            Key::Ip(ip) => hashed(
                "ip",
                &ip.map_or_else(
                    || "unknown".to_owned(),
                    |ip| crate::ratelimit::rate_limit_key(ip).to_string(),
                ),
            ),
            Key::Email(e) => hashed("email", e),
            Key::EmailNet(e, ip) => hashed("email-net", &format!("{e}|{}", net(ip))),
        }
    }
}

/// One limit to take `cost` tokens from.
#[derive(Debug, Clone, Copy)]
pub struct Check<'a> {
    pub limit: Limit,
    pub key: Key<'a>,
    pub cost: u32,
}

impl<'a> Check<'a> {
    pub fn new(limit: Limit, key: Key<'a>) -> Self {
        Self {
            limit,
            key,
            cost: 1,
        }
    }
    pub fn cost(mut self, cost: u32) -> Self {
        self.cost = cost;
        self
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    limit: Limit,
    scope: String,
    key: Uuid,
    rate: f64,
    cap: f64,
    cost: f64,
}

/// Tokens taken by [`Limiter::take`] (for [`Limiter::refund`]).
#[derive(Debug, Default)]
pub struct Taken {
    buckets: Vec<Bucket>,
}

impl Taken {
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Why [`Limiter::take`] did not take.
#[derive(Debug)]
pub struct Refusal {
    pub limit: Limit,
    pub retry_after: u32,
    /// The refusal is enforced (`false` in observe mode: let it through).
    pub enforced: bool,
}

impl Refusal {
    pub fn into_error(self) -> AppError {
        rate_limited(self.limit, self.retry_after)
    }
}

/// `429 rate_limited` naming `limit` in `details.limit`.
pub fn rate_limited(limit: Limit, retry_after: u32) -> AppError {
    AppError::rate_limited(retry_after).with_details(serde_json::json!({
        cc_protocol::quotas::DETAILS_LIMIT: limit.name(),
    }))
}

/// Effective quotas of one account (configuration + overrides).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    pub v2: bool,
    pub tombstone_cost_bytes: i64,
    pub max_vault_bytes: i64,
    pub max_vault_objects: i64,
    pub max_devices: i64,
    pub new_devices_per_day: i64,
}

type Overrides = Arc<HashMap<String, f64>>;

#[derive(Debug, Default)]
pub struct Limiter {
    overrides: Mutex<HashMap<Uuid, (Instant, Overrides)>>,
    audited: Mutex<HashMap<(Uuid, &'static str), Instant>>,
}

impl Limiter {
    /// Per-account overrides (cached up to [`OVERRIDES_TTL`]).
    pub async fn overrides(&self, db: &PgPool, user: UserId) -> AppResult<Overrides> {
        let id = Uuid::from(user);
        if let Some((at, o)) = self.overrides.lock().expect("lock").get(&id) {
            if at.elapsed() < OVERRIDES_TTL {
                return Ok(o.clone());
            }
        }
        let rows: Vec<(String, f64)> =
            sqlx::query_as("SELECT key, value FROM account_limits WHERE user_id = $1")
                .bind(id)
                .fetch_all(db)
                .await?;
        let o: Overrides = Arc::new(rows.into_iter().collect());
        self.overrides
            .lock()
            .expect("lock")
            .insert(id, (Instant::now(), o.clone()));
        Ok(o)
    }

    /// Effective quotas of `user`.
    pub async fn quotas(&self, db: &PgPool, config: &Config, user: UserId) -> AppResult<Quotas> {
        let o = self.overrides(db, user).await?;
        Ok(effective_quotas(config, &o))
    }

    /// Take tokens for `checks` (all or nothing). `Ok(Err(refusal))` when a
    /// bucket is short; the caller decides (most use [`Limiter::check`]).
    pub async fn take(
        &self,
        state: &AppState,
        user: Option<UserId>,
        checks: &[Check<'_>],
    ) -> AppResult<Result<Taken, Refusal>> {
        let cfg = &state.config.rate_limits;
        if !cfg.enabled || checks.is_empty() {
            return Ok(Ok(Taken::default()));
        }
        let overrides = match user {
            Some(u) if checks.iter().any(|c| !c.limit.def().auth) => {
                Some(self.overrides(&state.db, u).await?)
            }
            _ => None,
        };
        let mut buckets = Vec::new();
        for c in checks {
            let def = c.limit.def();
            let mut spec: LimitSpec = cfg.limits.get(c.limit);
            if let (false, Some(o)) = (def.auth, &overrides) {
                spec = spec.with_overrides(def.name, o);
            }
            let cost = f64::from(c.cost.max(1));
            let key = c.key.id();
            let mut push = |suffix: &str, rate: f64, cap: f64| {
                buckets.push(Bucket {
                    limit: c.limit,
                    scope: format!("{}{suffix}", def.name),
                    key,
                    rate,
                    cap,
                    cost: cost.min(cap),
                })
            };
            if spec.rate > 0.0 {
                push("", spec.rate, spec.burst.max(1.0));
            }
            if spec.per_hour > 0 {
                let n = f64::from(spec.per_hour);
                push(":h", n / 3600.0, n);
            }
            if spec.per_day > 0 {
                let n = f64::from(spec.per_day);
                push(":d", n / 86_400.0, n);
            }
        }
        if buckets.is_empty() {
            return Ok(Ok(Taken::default()));
        }
        // One locking order for every caller: no deadlocks between buckets.
        buckets.sort_by(|a, b| (&a.scope, a.key).cmp(&(&b.scope, b.key)));
        let started = Instant::now();
        let (refused, shortfall): (i32, f64) =
            sqlx::query_as("SELECT refused_index, shortfall FROM cc_rate_take($1, $2, $3, $4, $5)")
                .bind(buckets.iter().map(|b| b.scope.clone()).collect::<Vec<_>>())
                .bind(buckets.iter().map(|b| b.key).collect::<Vec<_>>())
                .bind(buckets.iter().map(|b| b.rate).collect::<Vec<_>>())
                .bind(buckets.iter().map(|b| b.cap).collect::<Vec<_>>())
                .bind(buckets.iter().map(|b| b.cost).collect::<Vec<_>>())
                .fetch_one(&state.db)
                .await?;
        metrics::histogram!("cc_rate_bucket_seconds").record(started.elapsed().as_secs_f64());
        let Some(b) = usize::try_from(refused)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| buckets.get(i))
        else {
            return Ok(Ok(Taken { buckets }));
        };
        let retry_after = (shortfall / b.rate).ceil().clamp(1.0, 86_400.0) as u32;
        let def = b.limit.def();
        let enforced = def.auth || cfg.mode == RateLimitMode::Enforce;
        if enforced {
            metrics::counter!("cc_rate_limited_total", "limiter" => def.name).increment(1);
        } else {
            metrics::counter!("cc_rate_limit_observed_total", "limiter" => def.name).increment(1);
        }
        if let Some(user) = user {
            self.audit(state, user, def.name, enforced);
        }
        Ok(Err(Refusal {
            limit: b.limit,
            retry_after,
            enforced,
        }))
    }

    /// Take tokens; `429` when an enforced limit is short.
    pub async fn check(
        &self,
        state: &AppState,
        user: Option<UserId>,
        checks: &[Check<'_>],
    ) -> AppResult<()> {
        match self.take(state, user, checks).await? {
            Err(r) if r.enforced => Err(r.into_error()),
            _ => Ok(()),
        }
    }

    /// Shorthand: one limit keyed by the account.
    pub async fn account(&self, state: &AppState, limit: Limit, user: UserId) -> AppResult<()> {
        self.check(state, Some(user), &[Check::new(limit, Key::Account(user))])
            .await
    }

    /// Give tokens back (e.g. a successful sign-in costs nothing).
    pub async fn refund(&self, db: &PgPool, taken: Taken) -> AppResult<()> {
        if taken.buckets.is_empty() {
            return Ok(());
        }
        let b = &taken.buckets;
        sqlx::query(
            "UPDATE rate_buckets r SET tokens = LEAST(t.cap, r.tokens + t.cost)
               FROM unnest($1::text[], $2::uuid[], $3::float8[], $4::float8[])
                    AS t(scope, key, cap, cost)
              WHERE r.scope = t.scope AND r.key = t.key",
        )
        .bind(b.iter().map(|b| b.scope.clone()).collect::<Vec<_>>())
        .bind(b.iter().map(|b| b.key).collect::<Vec<_>>())
        .bind(b.iter().map(|b| b.cap).collect::<Vec<_>>())
        .bind(b.iter().map(|b| b.cost).collect::<Vec<_>>())
        .execute(db)
        .await?;
        Ok(())
    }

    /// `limit_exceeded` / `quota_exceeded` audit event, at most once per hour
    /// per account and name (this replica remembers; all replicas share the
    /// `rate_counters` window). Runs in the background.
    pub fn audit(&self, state: &AppState, user: UserId, name: &'static str, enforced: bool) {
        self.audit_event(state, user, name, AuditType::LimitExceeded, enforced);
    }

    pub fn audit_quota(&self, state: &AppState, user: UserId, reason: &'static str) {
        self.audit_event(state, user, reason, AuditType::QuotaExceeded, true);
    }

    fn audit_event(
        &self,
        state: &AppState,
        user: UserId,
        name: &'static str,
        kind: AuditType,
        enforced: bool,
    ) {
        {
            let mut seen = self.audited.lock().expect("lock");
            let k = (Uuid::from(user), name);
            if seen.get(&k).is_some_and(|t| t.elapsed() < AUDIT_EVERY) {
                return;
            }
            seen.insert(k, Instant::now());
        }
        let state = state.clone();
        spawn_in_request(async move {
            let result = async {
                let mut tx = state.db.begin().await?;
                let key = hashed("audit", &format!("{}|{name}", Uuid::from(user)));
                let (count, _) = crate::devices::protection::bump(
                    &mut tx,
                    "limit_audit",
                    key,
                    crate::devices::protection::Window::Hour,
                )
                .await?;
                if count == 1 {
                    let field = if kind == AuditType::QuotaExceeded {
                        "reason"
                    } else {
                        "limit"
                    };
                    AuditEvent::new(kind)
                        .user(user)
                        .meta(serde_json::json!({
                            field: name,
                            "mode": if enforced { "enforce" } else { "observe" },
                        }))
                        .record(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                AppResult::Ok(())
            }
            .await;
            if let Err(err) = result {
                tracing::warn!(code = ?err.code(), "limit audit failed");
            }
        });
    }

    /// Drop expired cache entries; called periodically.
    pub fn housekeeping(&self) {
        self.overrides
            .lock()
            .expect("lock")
            .retain(|_, (t, _)| t.elapsed() < OVERRIDES_TTL);
        self.audited
            .lock()
            .expect("lock")
            .retain(|_, t| t.elapsed() < AUDIT_EVERY);
    }
}

/// Configuration quotas with per-account overrides applied.
pub fn effective_quotas(config: &Config, o: &HashMap<String, f64>) -> Quotas {
    let q = &config.quotas;
    let get = |k: &str, default: i64| o.get(k).map_or(default, |v| *v as i64);
    Quotas {
        v2: q.v2_enabled,
        tombstone_cost_bytes: q.tombstone_cost_bytes,
        max_vault_bytes: get("max_vault_bytes", config.max_vault_bytes).max(0),
        max_vault_objects: get("max_vault_objects", q.max_vault_objects).max(0),
        max_devices: get("max_devices_per_account", q.max_devices_per_account)
            .clamp(1, crate::config::limits::MAX_DEVICES_CEILING),
        new_devices_per_day: get(
            "new_devices_per_account_per_day",
            q.new_devices_per_account_per_day,
        )
        .max(0),
    }
}

/// Validate one `admin limits set` entry; returns the stored value.
pub fn parse_override(key: &str, value: &str) -> Result<f64, String> {
    use crate::config::limits::{parse_rate, CATALOG};
    if QUOTA_OVERRIDE_KEYS.contains(&key) {
        let v: i64 = value
            .trim()
            .parse()
            .map_err(|_| format!("{key}: expected a non-negative integer"))?;
        if v < 0 {
            return Err(format!("{key}: expected a non-negative integer"));
        }
        if key == "max_devices_per_account"
            && !(1..=crate::config::limits::MAX_DEVICES_CEILING).contains(&v)
        {
            return Err(format!("{key}: must be between 1 and 64"));
        }
        return Ok(v as f64);
    }
    for d in CATALOG.iter().filter(|d| !d.auth) {
        let Some(part) = key
            .strip_prefix(d.name)
            .and_then(|rest| rest.strip_prefix('_'))
        else {
            continue;
        };
        return match part {
            "rate" => parse_rate(value, d.period)
                .ok_or_else(|| format!("{key}: expected N or N/min|hour|day")),
            "burst" | "per_hour" | "per_day" => {
                let v: u32 = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("{key}: expected a non-negative integer"))?;
                if part == "burst" && v == 0 {
                    return Err(format!("{key}: must be >= 1"));
                }
                Ok(f64::from(v))
            }
            _ => continue,
        };
    }
    Err(format!(
        "unknown limit key {key:?} (see `admin limits show` for the keys)"
    ))
}

/// Human-readable value of an override (`show`).
pub fn display_override(key: &str, value: f64) -> String {
    use crate::config::limits::CATALOG;
    for d in CATALOG {
        if key == format!("{}_rate", d.name) {
            return format!(
                "{}/{}",
                round(value * d.period.seconds()),
                d.period.as_str()
            );
        }
    }
    round(value)
}

fn round(v: f64) -> String {
    if (v - v.round()).abs() < 1e-9 {
        format!("{}", v.round() as i64)
    } else {
        format!("{v:.3}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable_and_never_contain_input() {
        let a = Key::Email("someone@example.org").id();
        assert_eq!(a, Key::Email("someone@example.org").id());
        assert_ne!(a, Key::Email("other@example.org").id());
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.99".parse().unwrap();
        let ip3: IpAddr = "198.51.100.1".parse().unwrap();
        let e = "someone@example.org";
        assert_eq!(
            Key::EmailNet(e, Some(ip1)).id(),
            Key::EmailNet(e, Some(ip2)).id()
        );
        assert_ne!(
            Key::EmailNet(e, Some(ip1)).id(),
            Key::EmailNet(e, Some(ip3)).id()
        );
        assert_ne!(Key::Ip(Some(ip1)).id(), Key::Ip(Some(ip2)).id());
    }

    #[test]
    fn overrides_are_validated() {
        assert_eq!(parse_override("push_account_rate", "60/min"), Ok(1.0));
        assert_eq!(parse_override("push_account_rate", "600"), Ok(10.0));
        assert_eq!(parse_override("max_vault_objects", "5"), Ok(5.0));
        assert!(parse_override("max_devices_per_account", "65").is_err());
        assert!(parse_override("push_account_burst", "0").is_err());
        assert!(parse_override("login_email_rate", "1").is_err());
        assert!(parse_override("nope", "1").is_err());
        assert_eq!(display_override("push_account_rate", 1.0), "60/min");
        assert_eq!(display_override("max_vault_objects", 5.0), "5");
    }

    #[test]
    fn effective_quotas_respect_overrides_and_ceiling() {
        let config = Config::for_tests("postgres://localhost/unused");
        let o: HashMap<String, f64> = [
            ("max_devices_per_account".to_owned(), 100.0),
            ("max_vault_objects".to_owned(), 7.0),
        ]
        .into_iter()
        .collect();
        let q = effective_quotas(&config, &o);
        assert_eq!((q.max_devices, q.max_vault_objects), (64, 7));
        assert_eq!(q.max_vault_bytes, config.max_vault_bytes);
    }
}
