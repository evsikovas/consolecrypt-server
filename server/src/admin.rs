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
    pub email_verified: bool,
    pub devices: i64,
    pub vaults: i64,
}

pub async fn list_users(pool: &PgPool) -> anyhow::Result<Vec<UserSummary>> {
    Ok(sqlx::query_as(
        "SELECT u.id, u.email, u.status, u.email_verified_at IS NOT NULL AS email_verified,
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
