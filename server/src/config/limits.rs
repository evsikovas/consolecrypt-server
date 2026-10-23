// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Request limits and quotas (security audit S2): the catalogue of limits,
//! their defaults and the `CC_LIMIT_<NAME>_{RATE,BURST,PER_HOUR,PER_DAY}`
//! settings. The runtime lives in [`crate::limiter`].

use super::ConfigError;
use cc_protocol::quotas::limit as names;
use std::collections::HashMap;

/// Every limit stored in PostgreSQL token buckets (shared by all replicas).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Limit {
    PushDevice,
    PushAccount,
    MutationsAccount,
    UnknownDeleteAccount,
    ShareWriteAccount,
    ShareRevisionAccount,
    RecipientLookupAccount,
    EnrollmentAccount,
    TrustRequestDevice,
    TrustRequestAccount,
    VerificationAccount,
    AccountSecurity,
    WsConnectAccount,
    AuthIp,
    LoginEmail,
    LoginEmailTotal,
    RecoveryEmail,
    RecoveryEmailTotal,
}

/// Natural period of a limit's `_RATE` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Minute,
    Hour,
    Day,
}

impl Period {
    pub const fn seconds(self) -> f64 {
        match self {
            Period::Minute => 60.0,
            Period::Hour => 3600.0,
            Period::Day => 86_400.0,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Period::Minute => "min",
            Period::Hour => "hour",
            Period::Day => "day",
        }
    }
}

/// Static description and defaults of one limit.
#[derive(Debug, Clone, Copy)]
pub struct LimitDef {
    pub limit: Limit,
    /// `details.limit`, metric label, override/config key stem.
    pub name: &'static str,
    /// Default rate: `count` per `period` (0 = no rate bucket).
    pub count: u32,
    pub period: Period,
    /// Default bucket capacity (0 = `count`).
    pub burst: u32,
    /// Default extra hourly / daily ceilings (0 = none).
    pub per_hour: u32,
    pub per_day: u32,
    /// Sign-in limits: always enforced (they replace limits that were
    /// enforced before) and never overridden per account.
    pub auth: bool,
    /// Pre-0.2.2 setting that still sets the rate (in `period` units).
    pub legacy_env: Option<&'static str>,
}

const fn def(limit: Limit, name: &'static str, count: u32, period: Period) -> LimitDef {
    LimitDef {
        limit,
        name,
        count,
        period,
        burst: 0,
        per_hour: 0,
        per_day: 0,
        auth: false,
        legacy_env: None,
    }
}

const fn auth(mut d: LimitDef) -> LimitDef {
    d.auth = true;
    d
}

/// The catalogue, in a fixed order (also the bucket locking order).
pub const CATALOG: &[LimitDef] = &[
    LimitDef {
        burst: 60,
        ..def(Limit::PushDevice, names::PUSH_DEVICE, 120, Period::Minute)
    },
    def(Limit::PushAccount, names::PUSH_ACCOUNT, 300, Period::Minute),
    def(
        Limit::MutationsAccount,
        names::MUTATIONS_ACCOUNT,
        50_000,
        Period::Hour,
    ),
    def(
        Limit::UnknownDeleteAccount,
        names::UNKNOWN_DELETE_ACCOUNT,
        1000,
        Period::Day,
    ),
    LimitDef {
        burst: 20,
        ..def(
            Limit::ShareWriteAccount,
            names::SHARE_WRITE_ACCOUNT,
            60,
            Period::Hour,
        )
    },
    def(
        Limit::ShareRevisionAccount,
        names::SHARE_REVISION_ACCOUNT,
        600,
        Period::Hour,
    ),
    LimitDef {
        per_day: 300,
        ..def(
            Limit::RecipientLookupAccount,
            names::RECIPIENT_LOOKUP_ACCOUNT,
            30,
            Period::Minute,
        )
    },
    def(
        Limit::EnrollmentAccount,
        names::ENROLLMENT_ACCOUNT,
        30,
        Period::Hour,
    ),
    def(
        Limit::TrustRequestDevice,
        names::TRUST_REQUEST_DEVICE,
        10,
        Period::Hour,
    ),
    def(
        Limit::TrustRequestAccount,
        names::TRUST_REQUEST_ACCOUNT,
        30,
        Period::Day,
    ),
    def(
        Limit::VerificationAccount,
        names::VERIFICATION_ACCOUNT,
        20,
        Period::Hour,
    ),
    def(
        Limit::AccountSecurity,
        names::ACCOUNT_SECURITY,
        10,
        Period::Hour,
    ),
    def(
        Limit::WsConnectAccount,
        names::WS_CONNECT_ACCOUNT,
        60,
        Period::Minute,
    ),
    LimitDef {
        legacy_env: Some("CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE"),
        ..auth(def(Limit::AuthIp, names::AUTH_IP, 30, Period::Minute))
    },
    LimitDef {
        per_hour: 50,
        legacy_env: Some("CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE"),
        ..auth(def(
            Limit::LoginEmail,
            names::LOGIN_EMAIL,
            10,
            Period::Minute,
        ))
    },
    auth(def(
        Limit::LoginEmailTotal,
        names::LOGIN_EMAIL_TOTAL,
        200,
        Period::Hour,
    )),
    LimitDef {
        legacy_env: Some("CC_RATE_LIMIT_RECOVERY_PER_EMAIL_PER_HOUR"),
        ..auth(def(
            Limit::RecoveryEmail,
            names::RECOVERY_EMAIL,
            5,
            Period::Hour,
        ))
    },
    auth(def(
        Limit::RecoveryEmailTotal,
        "recovery_email_total",
        20,
        Period::Day,
    )),
];

impl Limit {
    pub fn def(self) -> &'static LimitDef {
        CATALOG
            .iter()
            .find(|d| d.limit == self)
            .expect("every limit is in the catalogue")
    }
    pub fn name(self) -> &'static str {
        self.def().name
    }
    pub fn from_name(name: &str) -> Option<Limit> {
        CATALOG.iter().find(|d| d.name == name).map(|d| d.limit)
    }
}

/// Effective settings of one limit. Every non-zero part is one bucket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LimitSpec {
    /// Tokens per second of the main bucket (0 = no main bucket).
    pub rate: f64,
    /// Capacity of the main bucket.
    pub burst: f64,
    pub per_hour: u32,
    pub per_day: u32,
}

impl LimitSpec {
    /// `count` per minute, burst `count`, no ceilings.
    pub fn per_minute(count: u32) -> Self {
        Self {
            rate: f64::from(count) / 60.0,
            burst: f64::from(count),
            per_hour: 0,
            per_day: 0,
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.rate <= 0.0 && self.per_hour == 0 && self.per_day == 0
    }

    fn default_of(d: &LimitDef) -> Self {
        let burst = if d.burst == 0 { d.count } else { d.burst };
        Self {
            rate: f64::from(d.count) / d.period.seconds(),
            burst: f64::from(burst),
            per_hour: d.per_hour,
            per_day: d.per_day,
        }
    }

    /// Apply per-account overrides (`<name>_rate` in tokens per second,
    /// `<name>_burst`, `<name>_per_hour`, `<name>_per_day`).
    pub fn with_overrides(mut self, name: &str, o: &HashMap<String, f64>) -> Self {
        if let Some(v) = o.get(&format!("{name}_rate")) {
            self.rate = v.max(0.0);
        }
        if let Some(v) = o.get(&format!("{name}_burst")) {
            self.burst = v.max(1.0);
        }
        if let Some(v) = o.get(&format!("{name}_per_hour")) {
            self.per_hour = v.clamp(0.0, f64::from(u32::MAX)) as u32;
        }
        if let Some(v) = o.get(&format!("{name}_per_day")) {
            self.per_day = v.clamp(0.0, f64::from(u32::MAX)) as u32;
        }
        self
    }
}

/// `enforce` refuses with `429`; `observe` only counts what would have been
/// refused (`cc_rate_limit_observed_total`) — for checking thresholds on a
/// live server before enforcing them. Sign-in limits always enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitMode {
    Enforce,
    Observe,
}

/// All PostgreSQL-backed limits.
#[derive(Debug, Clone)]
pub struct RequestLimits {
    specs: Vec<LimitSpec>,
}

impl RequestLimits {
    pub fn get(&self, limit: Limit) -> LimitSpec {
        self.specs[Self::index(limit)]
    }

    pub fn set(&mut self, limit: Limit, spec: LimitSpec) {
        self.specs[Self::index(limit)] = spec;
    }

    fn index(limit: Limit) -> usize {
        CATALOG
            .iter()
            .position(|d| d.limit == limit)
            .expect("every limit is in the catalogue")
    }

    pub(super) fn from_lookup(
        get: &impl Fn(&str) -> Option<String>,
    ) -> Result<RequestLimits, ConfigError> {
        let mut specs = Vec::with_capacity(CATALOG.len());
        for d in CATALOG {
            let mut spec = LimitSpec::default_of(d);
            let prefix = env_prefix(d.name);
            let rate_key = format!("{prefix}_RATE");
            let legacy = d.legacy_env.and_then(get);
            if let Some(v) = get(&rate_key) {
                spec.rate = parse_rate(&v, d.period).ok_or_else(|| {
                    ConfigError(format!("{rate_key}: expected N or N/min|hour|day"))
                })?;
                spec.burst = (spec.rate * d.period.seconds()).max(1.0);
            } else if let Some(v) = legacy {
                let n: u32 = v.trim().parse().map_err(|_| {
                    ConfigError(format!(
                        "{}: cannot parse value",
                        d.legacy_env.unwrap_or_default()
                    ))
                })?;
                spec.rate = f64::from(n) / d.period.seconds();
                spec.burst = f64::from(n.max(1));
            }
            let burst_key = format!("{prefix}_BURST");
            if let Some(v) = get(&burst_key) {
                let n: u32 =
                    v.trim().parse().ok().filter(|n| *n >= 1).ok_or_else(|| {
                        ConfigError(format!("{burst_key}: expected an integer >= 1"))
                    })?;
                spec.burst = f64::from(n);
            }
            for (suffix, slot) in [
                ("_PER_HOUR", &mut spec.per_hour),
                ("_PER_DAY", &mut spec.per_day),
            ] {
                let key = format!("{prefix}{suffix}");
                if let Some(v) = get(&key) {
                    *slot = v
                        .trim()
                        .parse()
                        .map_err(|_| ConfigError(format!("{key}: cannot parse value")))?;
                }
            }
            specs.push(spec);
        }
        Ok(RequestLimits { specs })
    }
}

/// `CC_LIMIT_<NAME>` for a limit name.
pub fn env_prefix(name: &str) -> String {
    format!("CC_LIMIT_{}", name.to_ascii_uppercase())
}

/// Every `CC_LIMIT_*` setting (for the native config file allow-list test).
pub fn env_keys() -> Vec<String> {
    CATALOG
        .iter()
        .flat_map(|d| {
            let p = env_prefix(d.name);
            ["_RATE", "_BURST", "_PER_HOUR", "_PER_DAY"].map(|s| format!("{p}{s}"))
        })
        .collect()
}

/// `N` (per `default` period) or `N/s|sec|min|m|hour|h|day|d` → tokens per
/// second. `0` disables the rate bucket.
pub fn parse_rate(value: &str, default: Period) -> Option<f64> {
    let value = value.trim();
    let (count, unit) = match value.split_once('/') {
        Some((c, u)) => (c.trim(), Some(u.trim())),
        None => (value, None),
    };
    let count: f64 = count
        .parse()
        .ok()
        .filter(|c: &f64| c.is_finite() && *c >= 0.0)?;
    let seconds = match unit {
        None => default.seconds(),
        Some("s" | "sec" | "second") => 1.0,
        Some("m" | "min" | "minute") => 60.0,
        Some("h" | "hour") => 3600.0,
        Some("d" | "day") => 86_400.0,
        Some(_) => return None,
    };
    Some(count / seconds)
}

/// Storage and device quotas (TR-1–TR-3). `v2_enabled` switches the new
/// behaviour (unknown deletes, tombstone and object accounting, device
/// limits); the counters are maintained either way.
#[derive(Debug, Clone)]
pub struct QuotaConfig {
    pub v2_enabled: bool,
    /// Bytes each tombstone costs against `CC_MAX_VAULT_BYTES`.
    pub tombstone_cost_bytes: i64,
    /// Live objects and tombstones per vault.
    pub max_vault_objects: i64,
    /// Active (not revoked) devices per account (≤ 64, the sharing limit).
    pub max_devices_per_account: i64,
    /// New devices per account in any 24 hours (0 = no limit).
    pub new_devices_per_account_per_day: i64,
}

/// Highest allowed `CC_MAX_DEVICES_PER_ACCOUNT` (recipient devices of one
/// shared item).
pub const MAX_DEVICES_CEILING: i64 = 64;

/// Quota keys that `admin limits` accepts besides the limit keys.
pub const QUOTA_OVERRIDE_KEYS: &[&str] = &[
    "max_vault_bytes",
    "max_vault_objects",
    "max_devices_per_account",
    "new_devices_per_account_per_day",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_parse_with_and_without_units() {
        assert_eq!(parse_rate("120", Period::Minute), Some(2.0));
        assert_eq!(parse_rate("3600/hour", Period::Minute), Some(1.0));
        assert_eq!(parse_rate("86400 / d", Period::Minute), Some(1.0));
        assert_eq!(parse_rate("0", Period::Hour), Some(0.0));
        assert_eq!(parse_rate("-1", Period::Hour), None);
        assert_eq!(parse_rate("5/week", Period::Hour), None);
        assert_eq!(parse_rate("x", Period::Hour), None);
    }

    #[test]
    fn catalogue_names_are_unique_and_lower_case() {
        let mut names: Vec<_> = CATALOG.iter().map(|d| d.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CATALOG.len());
        assert!(names
            .iter()
            .all(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '_')));
    }

    #[test]
    fn defaults_follow_the_spec_and_settings_override_them() {
        let none = |_: &str| None;
        let l = RequestLimits::from_lookup(&none).unwrap();
        let push = l.get(Limit::PushDevice);
        assert_eq!((push.rate, push.burst), (2.0, 60.0));
        let login = l.get(Limit::LoginEmail);
        assert_eq!((login.burst, login.per_hour), (10.0, 50));
        assert_eq!(l.get(Limit::RecipientLookupAccount).per_day, 300);

        let map: HashMap<&str, &str> = [
            ("CC_LIMIT_PUSH_DEVICE_RATE", "60/min"),
            ("CC_LIMIT_PUSH_DEVICE_BURST", "5"),
            ("CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE", "3"),
            ("CC_LIMIT_SHARE_WRITE_ACCOUNT_RATE", "0"),
        ]
        .into_iter()
        .collect();
        let get = |k: &str| map.get(k).map(|v| (*v).to_owned());
        let l = RequestLimits::from_lookup(&get).unwrap();
        assert_eq!(l.get(Limit::PushDevice).rate, 1.0);
        assert_eq!(l.get(Limit::PushDevice).burst, 5.0);
        assert_eq!(l.get(Limit::LoginEmail).burst, 3.0);
        assert!(l.get(Limit::ShareWriteAccount).is_unlimited());

        let bad = |k: &str| (k == "CC_LIMIT_PUSH_DEVICE_BURST").then(|| "0".to_owned());
        assert!(RequestLimits::from_lookup(&bad).is_err());
    }

    #[test]
    fn overrides_apply_per_part() {
        let spec = Limit::PushAccount.def();
        let base = LimitSpec::default_of(spec);
        let o: HashMap<String, f64> = [
            ("push_account_rate".to_owned(), 1.0),
            ("push_account_per_day".to_owned(), 7.0),
        ]
        .into_iter()
        .collect();
        let s = base.with_overrides("push_account", &o);
        assert_eq!((s.rate, s.burst, s.per_day), (1.0, base.burst, 7));
    }
}
