// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Server configuration from `CC_*` environment variables (see `.env.example`).
//!
//! Secret-bearing values (database URL, SMTP password) are redacted in `Debug`.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Default AGPL §13 source offer (ADR-0005). Operators of modified builds must
/// set `CC_SOURCE_CODE_URL` to where their modified source can be obtained.
pub const DEFAULT_SOURCE_CODE_URL: &str = "https://git.evsikov.net/publics/consolecrypt";

#[derive(Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    /// Secret (may contain a password). Never log.
    pub database_url: String,
    /// Optional password applied on top of the URL (keeps passwords out of
    /// URLs, no escaping needed). Secret. Never log.
    pub database_password: Option<String>,
    /// How long startup keeps retrying an unreachable database.
    pub database_connect_timeout: Duration,
    pub database_max_connections: u32,
    pub run_migrations: bool,
    /// Public base URL of this instance, used in emails. Optional.
    pub public_url: Option<String>,
    pub source_code_url: String,
    pub registration_open: bool,
    pub require_email_verification: bool,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub device_request_ttl: Duration,
    pub password_reset_ttl: Duration,
    pub email_verify_ttl: Duration,
    /// Trust `X-Forwarded-For` from exactly one reverse proxy in front.
    pub trust_proxy_headers: bool,
    /// Require the per-request device proof (protocol 1.5). Default true.
    /// When explicitly false (migration opt-out), invalid proofs are still
    /// rejected but missing ones are only counted.
    pub require_request_proof: bool,
    /// Experimental ADR-0008 backend; disabled until joint acceptance.
    pub object_sharing_enabled: bool,
    /// ADR-0009 kind capabilities; each requires general sharing and proofs.
    pub shared_groups_enabled: bool,
    pub shared_secrets_enabled: bool,
    /// Owner-online enrollment; requires sharing and strict device proofs.
    pub sharing_owner_online_enrollment_enabled: bool,
    pub event_bus: EventBusKind,
    pub metrics_listen: Option<SocketAddr>,
    pub log_format: LogFormat,
    pub hsts: bool,
    pub password_hashing: PasswordHashingConfig,
    pub rate_limits: RateLimitConfig,
    pub mail: MailConfig,
    /// Byte budget of one `changes`/`snapshot` page.
    pub sync_page_bytes: usize,
    /// Quota: bytes of live ciphertext per vault (push beyond → 413).
    pub max_vault_bytes: i64,
    /// Quota: vaults an account may own (create beyond → 403).
    pub max_vaults_per_account: i64,
    pub ws_ping_interval: Duration,
    /// How often a WebSocket re-checks that its session is still valid.
    pub ws_session_recheck_interval: Duration,
    /// Concurrent WebSocket connections per account (per replica).
    pub ws_max_connections_per_user: usize,
    /// Period of the maintenance/retention pass (zero disables it).
    pub maintenance_interval: Duration,
    pub retention: crate::jobs::RetentionConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventBusKind {
    /// PostgreSQL LISTEN/NOTIFY — works across replicas (default).
    Postgres,
    /// In-process only — single instance deployments and tests.
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone)]
pub struct PasswordHashingConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// Maximum concurrent Argon2 computations (CPU/memory DoS guard).
    pub max_concurrent: usize,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Public auth endpoints, per client IP, per minute (burst = same).
    pub auth_per_ip_per_minute: u32,
    /// Login attempts per email per minute.
    pub login_per_email_per_minute: u32,
    /// Forgot-password / account-recovery emails per email per hour.
    pub recovery_per_email_per_hour: u32,
    /// Attest / approve attempts per device per minute.
    pub proof_per_device_per_minute: u32,
}

#[derive(Clone)]
pub enum MailTransport {
    /// Mail is dropped (self-hosters use the admin CLI instead).
    Disabled,
    /// Development: every message is written as a file into `dir`.
    File { dir: PathBuf },
    Smtp {
        host: String,
        port: u16,
        username: Option<String>,
        /// Secret. Never log.
        password: Option<String>,
        tls: SmtpTls,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Implicit TLS (port 465).
    Tls,
    /// STARTTLS (port 587).
    StartTls,
    /// Plain SMTP — only for a local relay / dev mail catcher.
    None,
}

#[derive(Clone)]
pub struct MailConfig {
    pub transport: MailTransport,
    pub from: String,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid configuration: {0}")]
pub struct ConfigError(String);

impl Config {
    /// Read configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Self::from_lookup(|k| vars.get(k).cloned())
    }

    /// Read configuration through `get` (testable without touching the env).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let database_url = get("CC_DATABASE_URL")
            .or_else(|| get("DATABASE_URL"))
            .ok_or_else(|| ConfigError("CC_DATABASE_URL is required".into()))?;

        let secs = |k: &str, default: u64| -> Result<Duration, ConfigError> {
            Ok(Duration::from_secs(parse_or(get(k), k, default)?))
        };

        let mail_transport = match get("CC_MAIL_TRANSPORT").as_deref().unwrap_or("disabled") {
            "disabled" | "none" => MailTransport::Disabled,
            "file" => MailTransport::File {
                dir: PathBuf::from(get("CC_MAIL_DIR").unwrap_or_else(|| "./.dev-mail".into())),
            },
            "smtp" => MailTransport::Smtp {
                host: get("CC_SMTP_HOST")
                    .ok_or_else(|| ConfigError("CC_SMTP_HOST is required for smtp".into()))?,
                port: parse_or(get("CC_SMTP_PORT"), "CC_SMTP_PORT", 587u16)?,
                username: get("CC_SMTP_USERNAME"),
                password: get("CC_SMTP_PASSWORD"),
                tls: match get("CC_SMTP_TLS").as_deref().unwrap_or("starttls") {
                    "tls" => SmtpTls::Tls,
                    "starttls" => SmtpTls::StartTls,
                    "none" => SmtpTls::None,
                    other => {
                        return Err(ConfigError(format!("CC_SMTP_TLS: unknown value {other:?}")))
                    }
                },
            },
            other => {
                return Err(ConfigError(format!(
                    "CC_MAIL_TRANSPORT: unknown value {other:?} (disabled|file|smtp)"
                )))
            }
        };

        let metrics_listen = match get("CC_METRICS_LISTEN").as_deref() {
            None => Some(SocketAddr::from(([0, 0, 0, 0], 9090))),
            Some("off" | "disabled") => None,
            Some(v) => Some(
                v.parse()
                    .map_err(|_| ConfigError("CC_METRICS_LISTEN: invalid socket address".into()))?,
            ),
        };

        let config = Self {
            listen_addr: parse_or(
                get("CC_LISTEN_ADDR"),
                "CC_LISTEN_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 8080)),
            )?,
            database_url,
            database_password: get("CC_DATABASE_PASSWORD"),
            database_connect_timeout: secs("CC_DATABASE_CONNECT_TIMEOUT_SECS", 60)?,
            database_max_connections: parse_or(
                get("CC_DATABASE_MAX_CONNECTIONS"),
                "CC_DATABASE_MAX_CONNECTIONS",
                20,
            )?,
            run_migrations: parse_bool(get("CC_RUN_MIGRATIONS"), "CC_RUN_MIGRATIONS", true)?,
            public_url: get("CC_PUBLIC_URL"),
            source_code_url: get("CC_SOURCE_CODE_URL")
                .unwrap_or_else(|| DEFAULT_SOURCE_CODE_URL.to_owned()),
            registration_open: parse_bool(
                get("CC_REGISTRATION_OPEN"),
                "CC_REGISTRATION_OPEN",
                true,
            )?,
            require_email_verification: parse_bool(
                get("CC_REQUIRE_EMAIL_VERIFICATION"),
                "CC_REQUIRE_EMAIL_VERIFICATION",
                false,
            )?,
            access_token_ttl: secs("CC_ACCESS_TOKEN_TTL_SECS", 15 * 60)?,
            refresh_token_ttl: secs("CC_REFRESH_TOKEN_TTL_SECS", 30 * 24 * 3600)?,
            device_request_ttl: secs("CC_DEVICE_REQUEST_TTL_SECS", 24 * 3600)?,
            password_reset_ttl: secs("CC_PASSWORD_RESET_TTL_SECS", 3600)?,
            email_verify_ttl: secs("CC_EMAIL_VERIFY_TTL_SECS", 48 * 3600)?,
            // Secure by default (protocol 1.5): `false` is an explicit,
            // warned opt-out for migrating clients that do not sign yet.
            require_request_proof: parse_bool(
                get("CC_REQUIRE_REQUEST_PROOF"),
                "CC_REQUIRE_REQUEST_PROOF",
                true,
            )?,
            object_sharing_enabled: parse_bool(
                get("CC_OBJECT_SHARING_ENABLED"),
                "CC_OBJECT_SHARING_ENABLED",
                false,
            )?,
            shared_groups_enabled: parse_bool(
                get("CC_SHARED_GROUPS_ENABLED"),
                "CC_SHARED_GROUPS_ENABLED",
                false,
            )?,
            shared_secrets_enabled: parse_bool(
                get("CC_SHARED_SECRETS_ENABLED"),
                "CC_SHARED_SECRETS_ENABLED",
                false,
            )?,
            sharing_owner_online_enrollment_enabled: parse_bool(
                get("CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED"),
                "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED",
                false,
            )?,
            trust_proxy_headers: parse_bool(
                get("CC_TRUST_PROXY_HEADERS"),
                "CC_TRUST_PROXY_HEADERS",
                false,
            )?,
            event_bus: match get("CC_EVENT_BUS").as_deref().unwrap_or("postgres") {
                "postgres" => EventBusKind::Postgres,
                "local" => EventBusKind::Local,
                other => {
                    return Err(ConfigError(format!(
                        "CC_EVENT_BUS: unknown value {other:?}"
                    )))
                }
            },
            metrics_listen,
            log_format: match get("CC_LOG_FORMAT").as_deref().unwrap_or("json") {
                "json" => LogFormat::Json,
                "pretty" | "text" => LogFormat::Pretty,
                other => {
                    return Err(ConfigError(format!(
                        "CC_LOG_FORMAT: unknown value {other:?}"
                    )))
                }
            },
            hsts: parse_bool(get("CC_HSTS"), "CC_HSTS", true)?,
            password_hashing: PasswordHashingConfig {
                memory_kib: parse_or(
                    get("CC_ARGON2_MEMORY_KIB"),
                    "CC_ARGON2_MEMORY_KIB",
                    19 * 1024,
                )?,
                iterations: parse_or(get("CC_ARGON2_ITERATIONS"), "CC_ARGON2_ITERATIONS", 2)?,
                parallelism: parse_or(get("CC_ARGON2_PARALLELISM"), "CC_ARGON2_PARALLELISM", 1)?,
                // Bounded by default: each hash holds `memory_kib` of RAM.
                max_concurrent: parse_or(
                    get("CC_ARGON2_MAX_CONCURRENT"),
                    "CC_ARGON2_MAX_CONCURRENT",
                    std::thread::available_parallelism().map_or(2, |n| n.get().min(4)),
                )?,
            },
            rate_limits: RateLimitConfig {
                enabled: parse_bool(get("CC_RATE_LIMIT_ENABLED"), "CC_RATE_LIMIT_ENABLED", true)?,
                auth_per_ip_per_minute: parse_or(
                    get("CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE"),
                    "CC_RATE_LIMIT_AUTH_PER_IP_PER_MINUTE",
                    30,
                )?,
                login_per_email_per_minute: parse_or(
                    get("CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE"),
                    "CC_RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE",
                    10,
                )?,
                recovery_per_email_per_hour: parse_or(
                    get("CC_RATE_LIMIT_RECOVERY_PER_EMAIL_PER_HOUR"),
                    "CC_RATE_LIMIT_RECOVERY_PER_EMAIL_PER_HOUR",
                    5,
                )?,
                proof_per_device_per_minute: parse_or(
                    get("CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE"),
                    "CC_RATE_LIMIT_PROOF_PER_DEVICE_PER_MINUTE",
                    20,
                )?,
            },
            mail: MailConfig {
                transport: mail_transport,
                from: get("CC_MAIL_FROM")
                    .unwrap_or_else(|| "ConsoleCrypt <no-reply@localhost>".into()),
            },
            sync_page_bytes: parse_or(
                get("CC_SYNC_PAGE_BYTES"),
                "CC_SYNC_PAGE_BYTES",
                8 * 1024 * 1024,
            )?,
            max_vault_bytes: parse_or(
                get("CC_MAX_VAULT_BYTES"),
                "CC_MAX_VAULT_BYTES",
                1024 * 1024 * 1024,
            )?,
            max_vaults_per_account: parse_or(
                get("CC_MAX_VAULTS_PER_ACCOUNT"),
                "CC_MAX_VAULTS_PER_ACCOUNT",
                50,
            )?,
            ws_ping_interval: secs("CC_WS_PING_INTERVAL_SECS", 30)?,
            ws_session_recheck_interval: secs("CC_WS_SESSION_RECHECK_SECS", 30)?,
            ws_max_connections_per_user: parse_or(
                get("CC_WS_MAX_CONNECTIONS_PER_USER"),
                "CC_WS_MAX_CONNECTIONS_PER_USER",
                32,
            )?,
            maintenance_interval: secs("CC_MAINTENANCE_INTERVAL_SECS", 3600)?,
            retention: {
                let d = crate::jobs::RetentionConfig::default();
                let days = |k: &str, default: u32| parse_or(get(k), k, default);
                crate::jobs::RetentionConfig {
                    session_days: days("CC_RETENTION_SESSION_DAYS", d.session_days)?,
                    sync_mutation_days: days(
                        "CC_RETENTION_SYNC_MUTATION_DAYS",
                        d.sync_mutation_days,
                    )?,
                    audit_days: days("CC_RETENTION_AUDIT_DAYS", d.audit_days)?,
                    deleted_vault_days: days(
                        "CC_RETENTION_DELETED_VAULT_DAYS",
                        d.deleted_vault_days,
                    )?,
                    device_request_days: days(
                        "CC_RETENTION_DEVICE_REQUEST_DAYS",
                        d.device_request_days,
                    )?,
                }
            },
        };
        config.validate()?;
        Ok(config)
    }

    /// Reject values that would be dangerous or nonsensical at runtime
    /// (e.g. a retention of 2^31 days wrapping to a negative interval, or a
    /// zero interval panicking tokio timers).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let err = |m: &str| Err(ConfigError(m.to_owned()));
        if self.object_sharing_enabled && !self.require_request_proof {
            return err("object sharing requires CC_REQUIRE_REQUEST_PROOF=true");
        }
        if (self.shared_groups_enabled || self.shared_secrets_enabled)
            && (!self.object_sharing_enabled || !self.require_request_proof)
        {
            return err("shared groups/secrets require object sharing and strict request proofs");
        }
        if self.sharing_owner_online_enrollment_enabled
            && (!self.object_sharing_enabled || !self.require_request_proof)
        {
            return err("own-device enrollment requires object sharing and strict request proofs");
        }
        let r = &self.retention;
        for (name, days) in [
            ("CC_RETENTION_SESSION_DAYS", r.session_days),
            ("CC_RETENTION_SYNC_MUTATION_DAYS", r.sync_mutation_days),
            ("CC_RETENTION_AUDIT_DAYS", r.audit_days),
            ("CC_RETENTION_DELETED_VAULT_DAYS", r.deleted_vault_days),
            ("CC_RETENTION_DEVICE_REQUEST_DAYS", r.device_request_days),
        ] {
            if days > 36_500 {
                return err(&format!("{name}: at most 36500 days (0 keeps forever)"));
            }
        }
        if self.ws_ping_interval < Duration::from_secs(1) {
            return err("CC_WS_PING_INTERVAL_SECS must be >= 1");
        }
        if self.ws_session_recheck_interval < Duration::from_secs(1)
            || self.ws_session_recheck_interval > Duration::from_secs(30)
        {
            // ADR-0004: revocation must reach open sockets within 30 s.
            return err("CC_WS_SESSION_RECHECK_SECS must be between 1 and 30");
        }
        if self.access_token_ttl < Duration::from_secs(60)
            || self.access_token_ttl > Duration::from_secs(24 * 3600)
        {
            return err("CC_ACCESS_TOKEN_TTL_SECS must be between 60 and 86400");
        }
        if self.refresh_token_ttl < self.access_token_ttl {
            return err("CC_REFRESH_TOKEN_TTL_SECS must be >= CC_ACCESS_TOKEN_TTL_SECS");
        }
        if self.sync_page_bytes < 64 * 1024 {
            return err("CC_SYNC_PAGE_BYTES must be >= 65536");
        }
        if self.ws_max_connections_per_user == 0
            || self.max_vaults_per_account < 1
            || self.max_vault_bytes < 1024 * 1024
            || self.database_max_connections == 0
            || self.password_hashing.max_concurrent == 0
        {
            return err("limits must be positive (CC_MAX_VAULT_BYTES >= 1 MiB)");
        }
        Ok(())
    }

    /// Configuration for tests: cheap password hashing, local event bus off by
    /// default is NOT assumed — callers override what they need.
    pub fn for_tests(database_url: impl Into<String>) -> Self {
        let mut c = Self::from_lookup(|k| match k {
            "CC_DATABASE_URL" => Some(database_url_placeholder()),
            _ => None,
        })
        .expect("default test config is valid");
        c.database_url = database_url.into();
        c.listen_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        c.metrics_listen = None;
        c.log_format = LogFormat::Pretty;
        // Argon2 at its minimum so tests stay fast; production defaults above.
        c.password_hashing = PasswordHashingConfig {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
            max_concurrent: 8,
        };
        c.rate_limits.enabled = false;
        c.maintenance_interval = Duration::ZERO;
        c
    }
}

fn database_url_placeholder() -> String {
    "postgres://localhost/consolecrypt".into()
}

fn parse_or<T: FromStr>(v: Option<String>, key: &str, default: T) -> Result<T, ConfigError> {
    match v {
        None => Ok(default),
        Some(s) => s
            .trim()
            .parse()
            .map_err(|_| ConfigError(format!("{key}: cannot parse value"))),
    }
}

fn parse_bool(v: Option<String>, key: &str, default: bool) -> Result<bool, ConfigError> {
    match v.as_deref().map(str::trim) {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(ConfigError(format!("{key}: expected true/false"))),
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen_addr", &self.listen_addr)
            .field("database_url", &"<redacted>")
            .field("database_max_connections", &self.database_max_connections)
            .field("run_migrations", &self.run_migrations)
            .field("public_url", &self.public_url)
            .field("source_code_url", &self.source_code_url)
            .field("registration_open", &self.registration_open)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("require_request_proof", &self.require_request_proof)
            .field("object_sharing_enabled", &self.object_sharing_enabled)
            .field("shared_groups_enabled", &self.shared_groups_enabled)
            .field("shared_secrets_enabled", &self.shared_secrets_enabled)
            .field(
                "sharing_owner_online_enrollment_enabled",
                &self.sharing_owner_online_enrollment_enabled,
            )
            .field("event_bus", &self.event_bus)
            .field("metrics_listen", &self.metrics_listen)
            .field("log_format", &self.log_format)
            .field("rate_limits", &self.rate_limits)
            .field("mail", &self.mail)
            .field("maintenance_interval", &self.maintenance_interval)
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for MailTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailTransport::Disabled => f.write_str("disabled"),
            MailTransport::File { dir } => write!(f, "file({})", dir.display()),
            MailTransport::Smtp {
                host, port, tls, ..
            } => write!(f, "smtp({host}:{port}, {tls:?}, credentials redacted)"),
        }
    }
}

impl fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailConfig")
            .field("transport", &self.transport)
            .field("from", &self.from)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn requires_database_url() {
        assert!(cfg(&[]).is_err());
        let c = cfg(&[("CC_DATABASE_URL", "postgres://u:pw@h/db")]).unwrap();
        assert_eq!(c.listen_addr.port(), 8080);
        assert_eq!(c.access_token_ttl, Duration::from_secs(900));
        assert_eq!(c.event_bus, EventBusKind::Postgres);
        assert_eq!(c.source_code_url, DEFAULT_SOURCE_CODE_URL);
        assert!(
            c.require_request_proof,
            "request proofs are required by default"
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let c = cfg(&[
            ("CC_DATABASE_URL", "postgres://user:db-secret-pw@h/db"),
            ("CC_MAIL_TRANSPORT", "smtp"),
            ("CC_SMTP_HOST", "mail.example.org"),
            ("CC_SMTP_PASSWORD", "smtp-secret-pw"),
            ("CC_DATABASE_PASSWORD", "db-secret-pw2"),
        ])
        .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("db-secret-pw"));
        assert!(!dbg.contains("smtp-secret-pw"));
        assert!(!dbg.contains("db-secret-pw2"));
        assert_eq!(c.database_password.as_deref(), Some("db-secret-pw2"));
        assert!(c.password_hashing.max_concurrent <= 4);
        assert!(dbg.contains("mail.example.org"));
    }

    #[test]
    fn validation_rejects_dangerous_values() {
        let db = ("CC_DATABASE_URL", "x");
        assert!(cfg(&[db, ("CC_RETENTION_AUDIT_DAYS", "2147483648")]).is_err());
        assert!(cfg(&[db, ("CC_RETENTION_AUDIT_DAYS", "3000000000")]).is_err());
        assert!(cfg(&[db, ("CC_WS_PING_INTERVAL_SECS", "0")]).is_err());
        assert!(cfg(&[db, ("CC_WS_SESSION_RECHECK_SECS", "0")]).is_err());
        assert!(cfg(&[db, ("CC_WS_SESSION_RECHECK_SECS", "300")]).is_err());
        assert!(cfg(&[db, ("CC_ACCESS_TOKEN_TTL_SECS", "5")]).is_err());
        assert!(cfg(&[db, ("CC_RETENTION_AUDIT_DAYS", "0")]).is_ok());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(cfg(&[("CC_DATABASE_URL", "x"), ("CC_EVENT_BUS", "nats")]).is_err());
        assert!(cfg(&[("CC_DATABASE_URL", "x"), ("CC_RUN_MIGRATIONS", "maybe")]).is_err());
        let c = cfg(&[("CC_DATABASE_URL", "x"), ("CC_METRICS_LISTEN", "off")]).unwrap();
        assert!(c.metrics_listen.is_none());
    }
}

#[cfg(test)]
mod sharing_config_tests {
    use super::Config;

    #[test]
    fn extended_kinds_require_explicit_independent_flags_and_strict_sharing() {
        for flag in [
            "CC_SHARED_GROUPS_ENABLED",
            "CC_SHARED_SECRETS_ENABLED",
            "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED",
        ] {
            let load = |sharing: bool, proofs: bool, value: &str| {
                Config::from_lookup(|key| match key {
                    "CC_DATABASE_URL" => Some("postgres://localhost/unused".into()),
                    "CC_OBJECT_SHARING_ENABLED" => Some(sharing.to_string()),
                    "CC_REQUIRE_REQUEST_PROOF" => Some(proofs.to_string()),
                    key if key == flag => Some(value.into()),
                    _ => None,
                })
            };
            assert!(load(false, true, "true").is_err());
            assert!(load(true, false, "true").is_err());
            assert!(load(true, true, "invalid").is_err());
            let config = load(true, true, "true").unwrap();
            assert_eq!(
                config.shared_groups_enabled,
                flag == "CC_SHARED_GROUPS_ENABLED"
            );
            assert_eq!(
                config.shared_secrets_enabled,
                flag == "CC_SHARED_SECRETS_ENABLED"
            );
            assert_eq!(
                config.sharing_owner_online_enrollment_enabled,
                flag == "CC_SHARING_OWNER_ONLINE_ENROLLMENT_ENABLED"
            );
        }
        let defaults = Config::for_tests("postgres://localhost/unused");
        assert!(!defaults.shared_groups_enabled && !defaults.shared_secrets_enabled);
    }

    #[test]
    fn sharing_is_opt_in_and_requires_sender_constrained_tokens() {
        let mut config = Config::for_tests("postgres://localhost/unused");
        assert!(!config.object_sharing_enabled);
        config.object_sharing_enabled = true;
        assert!(config.validate().is_ok());
        config.require_request_proof = false;
        assert!(config.validate().is_err());
    }
}
