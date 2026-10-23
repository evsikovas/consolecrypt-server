// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! In-process keyed rate limiters (ADR-0201). Limits are per replica.
//!
//! They are the cheap first stage: the per-IP flood guard of the public auth
//! endpoints, vault-key guessing per device and authenticated reads (which
//! create no data and stay off the database on purpose). Everything that
//! writes, mails or costs real resources is limited in PostgreSQL by
//! [`crate::limiter`], shared by all replicas.

use crate::config::{RateLimitConfig, RateLimitMode};
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
    /// Only count what would be refused (`CC_RATE_LIMIT_MODE=observe`).
    observe: bool,
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
        Self {
            limiter,
            name,
            observe: false,
        }
    }

    fn observing(mut self, observe: bool) -> Self {
        self.observe = observe;
        self
    }

    /// Consume one unit for `key`, or fail with `429 rate_limited`.
    pub fn check(&self, key: &K) -> AppResult<()> {
        let Some(limiter) = &self.limiter else {
            return Ok(());
        };
        match limiter.check_key(key) {
            Ok(()) => Ok(()),
            Err(_) if self.observe => {
                metrics::counter!("cc_rate_limit_observed_total", "limiter" => self.name)
                    .increment(1);
                Ok(())
            }
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                metrics::counter!("cc_rate_limited_total", "limiter" => self.name).increment(1);
                Err(
                    AppError::rate_limited(wait.as_secs().saturating_add(1) as u32)
                        .with_details(serde_json::json!({ "limit": self.name })),
                )
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
    /// Public auth endpoints per client IP (first stage; the shared limit
    /// is `auth_ip` in PostgreSQL).
    pub auth_ip: Keyed<IpAddr>,
    /// Attest/approve proofs per device.
    pub proof_device: Keyed<Uuid>,
    /// Authenticated reads (GET) per device.
    pub read_device: Keyed<Uuid>,
}

impl RateLimiters {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let minute = Duration::from_secs(60);
        Self {
            auth_ip: Keyed::new(
                cc_protocol::quotas::limit::AUTH_IP,
                cfg.enabled,
                cfg.auth_per_ip_per_minute,
                minute,
            ),
            proof_device: Keyed::new(
                cc_protocol::quotas::limit::PROOF_DEVICE,
                cfg.enabled,
                cfg.proof_per_device_per_minute,
                minute,
            ),
            read_device: Keyed::new(
                cc_protocol::quotas::limit::READ_DEVICE,
                cfg.enabled && cfg.read_per_device_per_minute > 0,
                cfg.read_per_device_per_minute,
                minute,
            )
            .observing(cfg.mode == RateLimitMode::Observe),
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
        self.proof_device.retain_recent();
        self.read_device.retain_recent();
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

/// Network of a client address for the per-e-mail sign-in limits: IPv4 /24,
/// IPv6 /64. One subscriber or office usually owns such a network.
pub fn subnet_key(ip: IpAddr) -> IpAddr {
    match rate_limit_key(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        v6 => v6,
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
    fn subnets_are_ipv4_24_and_ipv6_64() {
        let a: IpAddr = "192.0.2.7".parse().unwrap();
        let b: IpAddr = "::ffff:192.0.2.200".parse().unwrap();
        let c: IpAddr = "192.0.3.7".parse().unwrap();
        assert_eq!(subnet_key(a), subnet_key(b));
        assert_ne!(subnet_key(a), subnet_key(c));
        let d: IpAddr = "2001:db8:1:2::9".parse().unwrap();
        assert_eq!(subnet_key(d), rate_limit_key(d));
    }

    #[test]
    fn observe_mode_counts_but_never_refuses() {
        let k: Keyed<u8> = Keyed::new("t", true, 1, Duration::from_secs(60)).observing(true);
        for _ in 0..5 {
            assert!(k.check(&1).is_ok());
        }
    }

    #[test]
    fn limits_after_burst() {
        let k: Keyed<u8> = Keyed::new("t", true, 3, Duration::from_secs(60));
        assert!(k.check(&1).is_ok());
        assert!(k.check(&1).is_ok());
        assert!(k.check(&1).is_ok());
        let err = k.check(&1).unwrap_err();
        assert_eq!(err.code(), cc_protocol::ErrorCode::RateLimited);
        assert!(format!("{err}").contains("too many requests"));
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
