// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Operator commands for self-hosters (`consolecrypt-server admin …`),
//! e.g. instances without SMTP. They act on *accounts* only: nothing here can
//! read or unlock vault data, and a password reset never grants vault access.
//!
//! Output goes to stdout (the operator's terminal), never to the logs.

use crate::audit::{AuditEvent, AuditType};
use crate::auth::sessions::{self, AccountTokenPurpose};
use crate::config::Config;
use crate::crypto::PasswordHasher;
use crate::events::Events;
use crate::util::validate_account_password;
use anyhow::{bail, Context as _};
use cc_protocol::auth::SecretString;
use cc_protocol::events::ServerEvent;
use cc_protocol::{UserId, VaultId};
use sqlx::PgPool;
use uuid::Uuid;

async fn find_user(pool: &PgPool, email: &str) -> anyhow::Result<UserId> {
    let id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE lower(email) = lower($1)")
            .bind(email.trim())
            .fetch_optional(pool)
            .await?;
    id.map(UserId::from)
        .with_context(|| "no account with this email")
}

async fn audit(pool: &PgPool, user: UserId, action: &str) -> anyhow::Result<()> {
    AuditEvent::new(AuditType::AdminAction)
        .user(user)
        .meta(serde_json::json!({ "action": action }))
        .record(pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Issue a single-use password-reset token (for instances without SMTP).
/// The user pastes it into the client ("Reset password").
pub async fn reset_token(pool: &PgPool, config: &Config, email: &str) -> anyhow::Result<String> {
    let user = find_user(pool, email).await?;
    let mut tx = pool.begin().await?;
    let token = sessions::issue_account_token(
        &mut tx,
        user,
        AccountTokenPurpose::PasswordReset,
        config.password_reset_ttl,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    tx.commit().await?;
    audit(pool, user, "reset_token").await?;
    Ok(token.token.expose_secret().to_owned())
}

/// Set a new account password and sign out every session.
pub async fn set_password(
    pool: &PgPool,
    config: &Config,
    email: &str,
    password: &SecretString,
) -> anyhow::Result<usize> {
    validate_account_password(password).map_err(|e| anyhow::anyhow!("{e}"))?;
    let user = find_user(pool, email).await?;
    let hash = PasswordHasher::new(&config.password_hashing)?
        .hash(password)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now()
          WHERE id = $1",
    )
    .bind(Uuid::from(user))
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    let revoked = sessions::revoke_user_sessions(&mut tx, user, None, "admin_set_password")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tx.commit().await?;
    audit(pool, user, "set_password").await?;
    Ok(revoked.len())
}

pub async fn verify_email(pool: &PgPool, email: &str) -> anyhow::Result<()> {
    let user = find_user(pool, email).await?;
    sqlx::query(
        "UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), updated_at = now()
          WHERE id = $1",
    )
    .bind(Uuid::from(user))
    .execute(pool)
    .await?;
    audit(pool, user, "verify_email").await
}

/// Disable (all sessions revoked) or re-enable an account.
pub async fn set_enabled(pool: &PgPool, email: &str, enabled: bool) -> anyhow::Result<()> {
    let user = find_user(pool, email).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET status = $2, updated_at = now() WHERE id = $1")
        .bind(Uuid::from(user))
        .bind(if enabled { "active" } else { "disabled" })
        .execute(&mut *tx)
        .await?;
    if !enabled {
        sessions::revoke_user_sessions(&mut tx, user, None, "admin_disabled")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    tx.commit().await?;
    audit(
        pool,
        user,
        if enabled {
            "enable_user"
        } else {
            "disable_user"
        },
    )
    .await
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserSummary {
    pub id: Uuid,
    pub email: String,
    pub status: String,
    /// `password`, `oidc`, `ldap` (linked identity) or `none`.
    pub sign_in: String,
    pub email_verified: bool,
    pub devices: i64,
    pub vaults: i64,
}

pub async fn list_users(pool: &PgPool) -> anyhow::Result<Vec<UserSummary>> {
    Ok(sqlx::query_as(
        "SELECT u.id, u.email, u.status,
                COALESCE((SELECT string_agg(i.provider, ',' ORDER BY i.provider)
                            FROM account_identities i WHERE i.account_id = u.id),
                         CASE WHEN u.password_hash IS NULL THEN 'none' ELSE 'password' END) AS sign_in,
                u.email_verified_at IS NOT NULL AS email_verified,
                (SELECT count(*) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL) AS devices,
                (SELECT count(*) FROM vault_members m JOIN vaults v ON v.id = m.vault_id
                  WHERE m.user_id = u.id AND m.revoked_at IS NULL AND v.state <> 'deleted') AS vaults
           FROM users u ORDER BY u.created_at",
    )
    .fetch_all(pool)
    .await?)
}

/// Rotate the epoch of one vault (or all) after restoring the server from a
/// backup, so clients detect the rollback (protocol 1.3). Connected clients
/// are nudged with `vault_changed`. Returns the number of vaults rotated.
pub async fn rotate_epoch(pool: &PgPool, vault: Option<VaultId>) -> anyhow::Result<usize> {
    let rotated: Vec<(Uuid, i64)> = sqlx::query_as(
        "UPDATE vaults v SET epoch = gen_random_uuid(), updated_at = now()
           FROM vault_sequences s
          WHERE s.vault_id = v.id AND v.state <> 'deleted'
            AND ($1::uuid IS NULL OR v.id = $1)
          RETURNING v.id, s.last_sequence",
    )
    .bind(vault.map(Uuid::from))
    .fetch_all(pool)
    .await?;
    if vault.is_some() && rotated.is_empty() {
        bail!("no such (non-deleted) vault");
    }
    AuditEvent::new(AuditType::AdminAction)
        .meta(serde_json::json!({ "action": "rotate_epoch", "vaults": rotated.len() }))
        .record(pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let events = Events::publisher(pool);
    for (id, latest_sequence) in &rotated {
        let vault_id = VaultId::from(*id);
        events
            .publish_vault(
                pool,
                vault_id,
                ServerEvent::VaultChanged {
                    vault_id,
                    latest_sequence: *latest_sequence,
                },
            )
            .await;
    }
    Ok(rotated.len())
}

/// Read a password from stdin (first line, trailing newline removed).
pub fn read_password_stdin() -> anyhow::Result<SecretString> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\r', '\n']).to_owned();
    if pw.is_empty() {
        bail!("no password on stdin");
    }
    Ok(SecretString::new(pw))
}

// ---------------------------------------------------------------------------
// Enterprise sign-in (protocol 1.9): emergency access (ТР-2a).

use crate::config::ProviderKind;
use crate::enterprise;

fn enterprise_source(config: &Config) -> anyhow::Result<(ProviderKind, String)> {
    let auth = &config.auth;
    match auth.enterprise_provider() {
        Some(ProviderKind::Oidc) => Ok((
            ProviderKind::Oidc,
            auth.oidc.as_ref().expect("validated").issuer.clone(),
        )),
        Some(ProviderKind::Ldap) => Ok((
            ProviderKind::Ldap,
            enterprise::ldap::issuer_for(auth.ldap.as_ref().expect("validated")),
        )),
        None => bail!(
            "enterprise sign-in is not configured (CC_AUTH_MODE=enterprise with its provider \
             settings is required for this command)"
        ),
    }
}

/// `admin auth status`: mode, provider, last check, linked accounts.
pub async fn auth_status(pool: &PgPool, config: &Config) -> anyhow::Result<Vec<String>> {
    let auth = &config.auth;
    let mut out = Vec::new();
    match auth.enterprise_provider() {
        None => out.push("mode: standard (email + account password)".to_owned()),
        Some(p) => {
            out.push(format!("mode: enterprise, provider: {}", p.as_str()));
            if let Some(o) = &auth.oidc {
                out.push(format!(
                    "oidc: preset {}, issuer {}, client id {}, scopes \"{}\"",
                    o.preset.as_str(),
                    o.issuer,
                    o.client_id,
                    o.scopes.join(" ")
                ));
                out.push(format!(
                    "oidc: email claim {}, required claim {}, MFA required {}",
                    o.email_claim,
                    o.required_claim
                        .as_ref()
                        .map(|(k, v)| format!("{k}={v}"))
                        .unwrap_or_else(|| "-".into()),
                    o.require_mfa
                ));
            }
            if let Some(l) = &auth.ldap {
                out.push(format!(
                    "ldap: {} ({}), base {}, id attribute {}, required group {}",
                    l.url,
                    if l.starttls { "STARTTLS" } else { "LDAPS" },
                    l.base_dn,
                    l.id_attr,
                    l.required_group.as_deref().unwrap_or("-")
                ));
                out.push(format!(
                    "ldap: lockout guard {} attempts / {} min per login (keep below the domain lockout threshold)",
                    l.max_failures,
                    l.failure_window.as_secs() / 60
                ));
            }
            out.push(format!(
                "display name: {}, allowed domains: {}, auto-create: {}, re-check every {} min, grace {} h",
                auth.display_name.as_deref().unwrap_or("-"),
                if auth.allowed_domains.is_empty() {
                    "any".to_owned()
                } else {
                    auth.allowed_domains.join(",")
                },
                auth.auto_create,
                auth.recheck_interval.as_secs() / 60,
                auth.recheck_grace.as_secs() / 3600
            ));
        }
    }
    let last: Option<(String, bool, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT provider, ok, detail, checked_at FROM auth_provider_status WHERE singleton",
    )
    .fetch_optional(pool)
    .await?;
    out.push(match last {
        Some((p, ok, detail, at)) => format!(
            "last check: {} {} at {} — {}",
            p,
            if ok { "OK" } else { "FAILED" },
            at.to_rfc3339(),
            detail
        ),
        None => "last check: none recorded".to_owned(),
    });
    let counts: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT provider, count(*),
                count(*) FILTER (WHERE check_unavailable_since IS NOT NULL)
           FROM account_identities GROUP BY provider ORDER BY provider",
    )
    .fetch_all(pool)
    .await?;
    for (p, n, unavailable) in counts {
        out.push(format!(
            "linked accounts ({p}): {n}, re-check pending because the source was unreachable: {unavailable}"
        ));
    }
    let unlinked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users u
          WHERE NOT EXISTS (SELECT 1 FROM account_identities i WHERE i.account_id = u.id)",
    )
    .fetch_one(pool)
    .await?;
    out.push(format!(
        "accounts without an identity (password accounts): {unlinked}"
    ));
    Ok(out)
}

/// `admin auth test [--login …]`: re-run the startup checks and, with a
/// login, a trial sign-in (LDAP, with the password from stdin) or a forced
/// re-check of the linked account (OIDC).
pub async fn auth_test(
    pool: &PgPool,
    config: &Config,
    login: Option<&str>,
    password: Option<SecretString>,
) -> anyhow::Result<Vec<String>> {
    let (kind, _) = enterprise_source(config)?;
    let mut out = Vec::new();
    let ent = match enterprise::Enterprise::init(config).await {
        Ok(Some(e)) => e,
        Ok(None) => bail!("enterprise sign-in is not configured"),
        Err(e) => {
            let _ = enterprise::record_status(pool, kind, false, &e.to_string()).await;
            return Err(e);
        }
    };
    let detail = ent.check().await?;
    enterprise::record_status(pool, kind, true, &detail).await?;
    out.push(format!("configuration: OK — {detail}"));
    let Some(login) = login else {
        return Ok(out);
    };
    match &ent.provider {
        enterprise::Provider::Ldap(l) => {
            let user = l
                .find_user(login)
                .await
                .map_err(|enterprise::ldap::Unavailable(why)| anyhow::anyhow!("LDAP: {why}"))?;
            let Some(user) = user else {
                out.push("login: no unique directory user matches CC_LDAP_USER_FILTER".to_owned());
                return Ok(out);
            };
            out.push(format!(
                "login: found, id {}, email {}, disabled {}, in required group {}",
                user.subject,
                user.email.as_deref().unwrap_or("-"),
                user.disabled,
                user.in_group
            ));
            if let Some(pw) = password {
                let ok = l
                    .verify_password(&user, &pw)
                    .await
                    .map_err(|enterprise::ldap::Unavailable(why)| anyhow::anyhow!("LDAP: {why}"))?;
                out.push(format!(
                    "password: {}",
                    if ok {
                        "accepted by the directory"
                    } else {
                        "REJECTED by the directory"
                    }
                ));
            }
        }
        enterprise::Provider::Oidc(_) => {
            let user = find_user(pool, login).await?;
            let mut cfg = config.clone();
            // The admin process must not start background work.
            cfg.maintenance_interval = std::time::Duration::ZERO;
            let state = crate::AppState::new(cfg, pool.clone()).await?;
            sqlx::query(
                "UPDATE account_identities SET checked_at = '-infinity'
                  WHERE account_id = $1 AND provider = 'oidc'",
            )
            .bind(Uuid::from(user))
            .execute(pool)
            .await?;
            let outcome = enterprise::recheck::run(&state, user)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            out.push(format!(
                "re-check of {login} at the IdP: {}",
                match outcome {
                    enterprise::recheck::Outcome::Ok => "OK (refresh grant accepted)",
                    enterprise::recheck::Outcome::Grace
                    | enterprise::recheck::Outcome::Unavailable => "IdP unreachable",
                    enterprise::recheck::Outcome::Revoked =>
                        "REFUSED by the IdP — all sessions of the account were revoked",
                    enterprise::recheck::Outcome::ReauthRequired =>
                        "impossible: no IdP refresh token stored (request offline access)",
                }
            ));
        }
    }
    Ok(out)
}

/// `admin identity link`: bind an account to an identity by hand (instead of
/// the automatic link on first sign-in). Removes the account password and
/// signs out its sessions.
pub async fn identity_link(
    pool: &PgPool,
    config: &Config,
    email: &str,
    subject: &str,
    issuer: Option<&str>,
) -> anyhow::Result<usize> {
    let (kind, default_issuer) = enterprise_source(config)?;
    let issuer = issuer.map(str::to_owned).unwrap_or(default_issuer);
    let subject = subject.trim();
    if subject.is_empty() || subject.len() > 1024 {
        bail!("invalid --subject");
    }
    if kind == ProviderKind::Ldap
        && config
            .auth
            .ldap
            .as_ref()
            .is_some_and(|l| l.id_attr.eq_ignore_ascii_case("objectGUID"))
        && enterprise::ldap::parse_guid(subject).is_none()
    {
        bail!("--subject must be the objectGUID as a GUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)");
    }
    let subject = if kind == ProviderKind::Ldap {
        subject.to_ascii_lowercase()
    } else {
        subject.to_owned()
    };
    let user = find_user(pool, email).await?;
    let mut tx = pool.begin().await?;
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT account_id FROM account_identities WHERE provider = $1 AND issuer = $2 AND subject = $3",
    )
    .bind(kind.as_str())
    .bind(&issuer)
    .bind(&subject)
    .fetch_optional(&mut *tx)
    .await?;
    match owner {
        Some(o) if o == Uuid::from(user) => bail!("already linked to this identity"),
        Some(_) => bail!("this identity is linked to another account (unlink it there first)"),
        None => {}
    }
    let inserted = sqlx::query(
        "INSERT INTO account_identities (account_id, provider, issuer, subject, checked_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(Uuid::from(user))
    .bind(kind.as_str())
    .bind(&issuer)
    .bind(&subject)
    .execute(&mut *tx)
    .await;
    if let Err(e) = inserted {
        if crate::error::is_unique_violation(&e) {
            bail!(
                "the account is already linked to another identity of this source (unlink first)"
            );
        }
        return Err(e.into());
    }
    sqlx::query(
        "UPDATE users SET password_hash = NULL, updated_at = now(),
                email_verified_at = COALESCE(email_verified_at, now())
          WHERE id = $1",
    )
    .bind(Uuid::from(user))
    .execute(&mut *tx)
    .await?;
    let revoked = sessions::revoke_user_sessions(&mut tx, user, None, "identity_linked")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    AuditEvent::new(AuditType::IdentityLinked)
        .user(user)
        .meta(serde_json::json!({ "provider": kind.as_str(), "via": "admin" }))
        .record(&mut *tx)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tx.commit().await?;
    publish_revoked(pool, user, &revoked).await;
    Ok(revoked.len())
}

/// `admin identity unlink`: remove the account's identities (all, or the one
/// with `subject`). The account keeps its data; its next enterprise sign-in
/// links or creates again.
pub async fn identity_unlink(
    pool: &PgPool,
    email: &str,
    subject: Option<&str>,
) -> anyhow::Result<u64> {
    let user = find_user(pool, email).await?;
    let n = sqlx::query(
        "DELETE FROM account_identities
          WHERE account_id = $1 AND ($2::text IS NULL OR lower(subject) = lower($2))",
    )
    .bind(Uuid::from(user))
    .bind(subject.map(str::trim))
    .execute(pool)
    .await?
    .rows_affected();
    if n == 0 {
        bail!("no matching identity on this account");
    }
    AuditEvent::new(AuditType::IdentityUnlinked)
        .user(user)
        .meta(serde_json::json!({ "identities": n, "via": "admin" }))
        .record(pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(n)
}

/// `admin session revoke --email …`: sign out every session of an account.
pub async fn session_revoke(pool: &PgPool, email: &str) -> anyhow::Result<usize> {
    let user = find_user(pool, email).await?;
    let mut tx = pool.begin().await?;
    let revoked = sessions::revoke_user_sessions(&mut tx, user, None, "admin_revoked")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tx.commit().await?;
    AuditEvent::new(AuditType::AdminAction)
        .user(user)
        .meta(serde_json::json!({ "action": "session_revoke", "sessions": revoked.len() }))
        .record(pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tracing::info!(user_id = %Uuid::from(user), sessions = revoked.len(), "sessions revoked by the administrator");
    publish_revoked(pool, user, &revoked).await;
    Ok(revoked.len())
}

async fn publish_revoked(pool: &PgPool, user: UserId, revoked: &[cc_protocol::SessionId]) {
    let events = Events::publisher(pool);
    for session_id in revoked {
        events
            .publish_user(
                user,
                ServerEvent::SessionRevoked {
                    session_id: *session_id,
                },
            )
            .await;
    }
}

/// `admin limits set --email … key=value…`: per-account overrides of request
/// limits and quotas (running servers pick them up within 30 seconds).
/// Returns the stored keys with their normalised values.
pub async fn limits_set(
    pool: &PgPool,
    email: &str,
    pairs: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    if pairs.is_empty() {
        bail!("give at least one key=value (see `admin limits show`)");
    }
    let mut parsed = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("{pair:?}: expected key=value"))?;
        let key = key.trim().to_ascii_lowercase();
        let value = crate::limiter::parse_override(&key, value).map_err(|e| anyhow::anyhow!(e))?;
        parsed.push((key, value));
    }
    let user = find_user(pool, email).await?;
    let mut tx = pool.begin().await?;
    for (key, value) in &parsed {
        sqlx::query(
            "INSERT INTO account_limits (user_id, key, value) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        )
        .bind(Uuid::from(user))
        .bind(key)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    AuditEvent::new(AuditType::AdminAction)
        .user(user)
        .meta(serde_json::json!({
            "action": "limits_set",
            "keys": parsed.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        }))
        .record(pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(parsed
        .into_iter()
        .map(|(k, v)| {
            let shown = crate::limiter::display_override(&k, v);
            (k, shown)
        })
        .collect())
}

/// `admin limits reset --email … [key…]`: drop overrides (all without keys).
pub async fn limits_reset(pool: &PgPool, email: &str, keys: &[String]) -> anyhow::Result<u64> {
    let user = find_user(pool, email).await?;
    let keys: Vec<String> = keys.iter().map(|k| k.trim().to_ascii_lowercase()).collect();
    let n = sqlx::query(
        "DELETE FROM account_limits
          WHERE user_id = $1 AND (cardinality($2::text[]) = 0 OR key = ANY($2))",
    )
    .bind(Uuid::from(user))
    .bind(&keys)
    .execute(pool)
    .await?
    .rows_affected();
    AuditEvent::new(AuditType::AdminAction)
        .user(user)
        .meta(serde_json::json!({ "action": "limits_reset", "keys": keys, "removed": n }))
        .record(pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(n)
}

/// `admin limits show [--email …]`: the effective limits and quotas (of the
/// account, with its overrides marked `*`) and their override keys.
pub async fn limits_show(
    pool: &PgPool,
    config: &Config,
    email: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    use crate::config::limits::CATALOG;
    use std::collections::HashMap;
    let overrides: HashMap<String, f64> = match email {
        Some(email) => {
            let user = find_user(pool, email).await?;
            sqlx::query_as::<_, (String, f64)>(
                "SELECT key, value FROM account_limits WHERE user_id = $1 ORDER BY key",
            )
            .bind(Uuid::from(user))
            .fetch_all(pool)
            .await?
            .into_iter()
            .collect()
        }
        None => HashMap::new(),
    };
    let rl = &config.rate_limits;
    let mut out = vec![format!(
        "request limits: {} (CC_RATE_LIMIT_ENABLED={}); sign-in limits always enforce",
        match rl.mode {
            crate::config::RateLimitMode::Enforce => "enforce",
            crate::config::RateLimitMode::Observe => "observe",
        },
        rl.enabled
    )];
    let mark = |key: &str| if overrides.contains_key(key) { "*" } else { "" };
    for d in CATALOG {
        let mut spec = rl.limits.get(d.limit);
        if !d.auth {
            spec = spec.with_overrides(d.name, &overrides);
        }
        let n = d.name;
        let per = |v: u32| {
            if v == 0 {
                "-".to_owned()
            } else {
                v.to_string()
            }
        };
        out.push(format!(
            "{n:<26} rate={}{} burst={}{} per_hour={}{} per_day={}{}{}",
            if spec.rate > 0.0 {
                crate::limiter::display_override(&format!("{n}_rate"), spec.rate)
            } else {
                "-".to_owned()
            },
            mark(&format!("{n}_rate")),
            if spec.rate > 0.0 {
                format!("{}", spec.burst.round() as i64)
            } else {
                "-".to_owned()
            },
            mark(&format!("{n}_burst")),
            per(spec.per_hour),
            mark(&format!("{n}_per_hour")),
            per(spec.per_day),
            mark(&format!("{n}_per_day")),
            if d.auth {
                "  (sign-in, not per account)"
            } else {
                ""
            },
        ));
    }
    let q = crate::limiter::effective_quotas(config, &overrides);
    out.push(format!(
        "quotas: CC_QUOTAS_V2_ENABLED={} tombstone_cost_bytes={}",
        q.v2, q.tombstone_cost_bytes
    ));
    for (key, value) in [
        ("max_vault_bytes", q.max_vault_bytes),
        ("max_vault_objects", q.max_vault_objects),
        ("max_devices_per_account", q.max_devices),
        ("new_devices_per_account_per_day", q.new_devices_per_day),
    ] {
        out.push(format!("{key:<32} {value}{}", mark(key)));
    }
    out.push(
        "override keys: <limit>_rate (N or N/min|hour|day), <limit>_burst, <limit>_per_hour, \
         <limit>_per_day, and the quota names above"
            .to_owned(),
    );
    Ok(out)
}
