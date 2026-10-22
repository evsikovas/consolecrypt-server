// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Directory lockout guard for `/v1/auth/ldap/login`.
//!
//! Failed binds count towards the domain's account lockout policy, so an
//! attacker could lock employees out through this endpoint. Attempts are
//! therefore metered in PostgreSQL (shared by all replicas), per fixed window
//! of `CC_LDAP_FAILURE_WINDOW_MINUTES`:
//!
//! * per normalised login and per directory user: an attempt is *reserved*
//!   before the directory is contacted (so concurrent requests on several
//!   replicas cannot exceed the limit) and the counters are cleared after a
//!   successful sign-in. After `CC_LDAP_MAX_FAILURES` attempts further ones
//!   are refused with `429 rate_limited` + `Retry-After` without contacting
//!   the directory, until the window has passed. Unknown and existing logins
//!   behave the same (no account enumeration).
//! * per client IP (`CC_LDAP_MAX_FAILURES_PER_IP`, 0 = off): failures only.
//!
//! `CC_LDAP_MAX_FAILURES` must stay below the domain's lockout threshold.
//! Keys are SHA-256 digests; logins are never stored in clear.

use crate::error::{AppError, AppResult};
use sqlx::PgPool;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Login,
    User,
    Ip,
}

impl Scope {
    const fn as_str(self) -> &'static str {
        match self {
            Scope::Login => "login",
            Scope::User => "user",
            Scope::Ip => "ip",
        }
    }
}

/// Normalised login: trimmed, lower-case, `DOMAIN\` kept (it is part of
/// what the user typed; the per-user key covers aliases of one account).
pub fn normalize_login(login: &str) -> String {
    login.trim().to_lowercase()
}

pub fn key(scope: Scope, value: &str) -> [u8; 32] {
    crate::crypto::sha256(format!("cc-ldap-lockout-v1|{}|{value}", scope.as_str()).as_bytes())
}

pub fn ip_key(ip: IpAddr) -> [u8; 32] {
    key(Scope::Ip, &crate::ratelimit::rate_limit_key(ip).to_string())
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// Reserve one attempt for `key`; `Err(429)` when the window's budget is
/// spent (the directory must then not be contacted).
pub async fn reserve(
    db: &PgPool,
    scope: Scope,
    key: &[u8; 32],
    max: u32,
    window: Duration,
) -> AppResult<()> {
    let (count, retry): (i32, f64) = sqlx::query_as(
        "INSERT INTO ldap_login_failures AS f (scope, key, window_start, failures)
         VALUES ($1, $2, now(), 1)
         ON CONFLICT (scope, key) DO UPDATE SET
             window_start = CASE WHEN f.window_start <= now() - make_interval(secs => $3)
                                 THEN now() ELSE f.window_start END,
             failures = CASE WHEN f.window_start <= now() - make_interval(secs => $3)
                             THEN 1 ELSE f.failures + 1 END
         RETURNING failures,
                   EXTRACT(EPOCH FROM (window_start + make_interval(secs => $3) - now()))::float8",
    )
    .bind(scope.as_str())
    .bind(&key[..])
    .bind(secs(window))
    .fetch_one(db)
    .await?;
    if count > i32::try_from(max).unwrap_or(i32::MAX) {
        metrics::counter!("cc_ldap_lockout_guard_total", "scope" => scope.as_str()).increment(1);
        return Err(AppError::rate_limited(retry.ceil().max(1.0) as u32));
    }
    Ok(())
}

/// Refuse when `key` already has `max` failures in the window (IP scope).
pub async fn check(
    db: &PgPool,
    scope: Scope,
    key: &[u8; 32],
    max: u32,
    window: Duration,
) -> AppResult<()> {
    if max == 0 {
        return Ok(());
    }
    let row: Option<(i32, f64)> = sqlx::query_as(
        "SELECT failures,
                EXTRACT(EPOCH FROM (window_start + make_interval(secs => $3) - now()))::float8
           FROM ldap_login_failures
          WHERE scope = $1 AND key = $2 AND window_start > now() - make_interval(secs => $3)",
    )
    .bind(scope.as_str())
    .bind(&key[..])
    .bind(secs(window))
    .fetch_optional(db)
    .await?;
    match row {
        Some((n, retry)) if n >= i32::try_from(max).unwrap_or(i32::MAX) => {
            metrics::counter!("cc_ldap_lockout_guard_total", "scope" => scope.as_str())
                .increment(1);
            Err(AppError::rate_limited(retry.ceil().max(1.0) as u32))
        }
        _ => Ok(()),
    }
}

/// Count a failure (IP scope; login/user scopes reserve up front).
pub async fn record_failure(
    db: &PgPool,
    scope: Scope,
    key: &[u8; 32],
    window: Duration,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO ldap_login_failures AS f (scope, key, window_start, failures)
         VALUES ($1, $2, now(), 1)
         ON CONFLICT (scope, key) DO UPDATE SET
             window_start = CASE WHEN f.window_start <= now() - make_interval(secs => $3)
                                 THEN now() ELSE f.window_start END,
             failures = CASE WHEN f.window_start <= now() - make_interval(secs => $3)
                             THEN 1 ELSE f.failures + 1 END",
    )
    .bind(scope.as_str())
    .bind(&key[..])
    .bind(secs(window))
    .execute(db)
    .await?;
    Ok(())
}

/// Forget the attempts of `key` (after a successful sign-in).
pub async fn clear(db: &PgPool, scope: Scope, key: &[u8; 32]) -> AppResult<()> {
    sqlx::query("DELETE FROM ldap_login_failures WHERE scope = $1 AND key = $2")
        .bind(scope.as_str())
        .bind(&key[..])
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_and_normalised() {
        assert_eq!(normalize_login("  Alice@ACME.test "), "alice@acme.test");
        assert_ne!(key(Scope::Login, "a"), key(Scope::User, "a"));
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::2".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
    }
}
