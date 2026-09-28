// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! In-process keyed rate limiters (ADR-0201). Limits are per replica.

use crate::config::RateLimitConfig;
use crate::error::{AppError, AppResult};
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;
use uuid::Uuid;

pub struct Keyed<K: Hash + Eq + Clone> {
    limiter: Option<DefaultKeyedRateLimiter<K>>,
    name: &'static str,
}

impl<K: Hash + Eq + Clone> fmt::Debug for Keyed<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyed")
            .field("name", &self.name)
            .field("enabled", &self.limiter.is_some())
            .finish()
    }
}

impl<K: Hash + Eq + Clone> Keyed<K> {
    fn new(name: &'static str, enabled: bool, count: u32, per: Duration) -> Self {
        let limiter = enabled.then(|| {
            let burst = NonZeroU32::new(count.max(1)).expect("non-zero");
            let period = per / burst.get();
            let quota = Quota::with_period(period.max(Duration::from_millis(1)))
                .expect("non-zero period")
                .allow_burst(burst);
            RateLimiter::keyed(quota)
        });
        Self { limiter, name }
    }

    /// Consume one unit for `key`, or fail with `429 rate_limited`.
    pub fn check(&self, key: &K) -> AppResult<()> {
        let Some(limiter) = &self.limiter else {
            return Ok(());
        };
        match limiter.check_key(key) {
            Ok(()) => Ok(()),
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                metrics::counter!("cc_rate_limited_total", "limiter" => self.name).increment(1);
                Err(AppError::rate_limited(
                    wait.as_secs().saturating_add(1) as u32
                ))
            }
        }
    }

    fn retain_recent(&self) {
        if let Some(l) = &self.limiter {
            l.retain_recent();
            l.shrink_to_fit();
        }
    }
}

/// All limiters of one server instance.
#[derive(Debug)]
pub struct RateLimiters {
    /// Public auth endpoints per client IP.
    pub auth_ip: Keyed<IpAddr>,
    /// Login attempts per (lower-cased) email.
    pub login_email: Keyed<String>,
    /// Password-reset / account-recovery mails per email.
    pub recovery_email: Keyed<String>,
    /// Attest/approve proofs per device.
    pub proof_device: Keyed<Uuid>,
}

impl RateLimiters {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let minute = Duration::from_secs(60);
        Self {
            auth_ip: Keyed::new("auth_ip", cfg.enabled, cfg.auth_per_ip_per_minute, minute),
            login_email: Keyed::new(
                "login_email",
                cfg.enabled,
                cfg.login_per_email_per_minute,
                minute,
            ),
            recovery_email: Keyed::new(
                "recovery_email",
                cfg.enabled,
                cfg.recovery_per_email_per_hour,
                Duration::from_secs(3600),
            ),
            proof_device: Keyed::new(
                "proof_device",
                cfg.enabled,
                cfg.proof_per_device_per_minute,
                minute,
            ),
        }
    }

    /// Check the per-IP auth limiter when the IP is known. IPv6 clients are
    /// keyed by their /64 (one subscriber usually owns a whole /64).
    pub fn check_auth_ip(&self, ip: Option<IpAddr>) -> AppResult<()> {
        match ip {
            Some(ip) => self.auth_ip.check(&rate_limit_key(ip)),
            None => Ok(()),
        }
    }

    /// Drop idle keys; called periodically.
    pub fn housekeeping(&self) {
        self.auth_ip.retain_recent();
        self.login_email.retain_recent();
        self.recovery_email.retain_recent();
        self.proof_device.retain_recent();
    }
}

/// Rate-limit key of a client address: IPv4 as is (also when IPv4-mapped),
/// IPv6 truncated to its /64 prefix.
pub fn rate_limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_is_keyed_by_prefix() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(rate_limit_key(a), rate_limit_key(b));
        assert_ne!(rate_limit_key(a), rate_limit_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(
            rate_limit_key(mapped),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn limits_after_burst() {
        let k: Keyed<u8> = Keyed::new("t", true, 3, Duration::from_secs(60));
        assert!(k.check(&1).is_ok());
        assert!(k.check(&1).is_ok());
        assert!(k.check(&1).is_ok());
        let err = k.check(&1).unwrap_err();
        assert_eq!(err.code(), cc_protocol::ErrorCode::RateLimited);
        // Other keys are independent.
        assert!(k.check(&2).is_ok());
    }

    #[test]
    fn disabled_never_limits() {
        let k: Keyed<u8> = Keyed::new("t", false, 1, Duration::from_secs(60));
        for _ in 0..10 {
            assert!(k.check(&1).is_ok());
        }
    }
}
