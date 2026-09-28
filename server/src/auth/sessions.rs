// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Sessions, token rotation with reuse detection, single-use account tokens.

use super::middleware;
use crate::audit::{AuditEvent, AuditType};
use crate::config::Config;
use crate::crypto::{self, IssuedToken, TokenKind};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use cc_protocol::auth::{SecretString, TokenPair};
use cc_protocol::devices::RequestProof;
use cc_protocol::events::ServerEvent;
use cc_protocol::{DeviceId, ErrorCode, SessionId, UserId};
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use std::net::IpAddr;
use std::time::Duration;
use uuid::Uuid;

fn after(ttl: Duration) -> DateTime<Utc> {
    Utc::now() + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::MAX)
}

/// Start a new session (refresh-token family) for `device_id`.
pub async fn create_session(
    conn: &mut PgConnection,
    config: &Config,
    user_id: UserId,
    device_id: DeviceId,
) -> AppResult<TokenPair> {
    let session_id = SessionId::new();
    let access = crypto::issue_token(TokenKind::Access);
    let refresh = crypto::issue_token(TokenKind::Refresh);
    let access_expires_at = after(config.access_token_ttl);
    let refresh_expires_at = after(config.refresh_token_ttl);

    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, access_token_hash, access_expires_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::from(session_id))
    .bind(Uuid::from(user_id))
    .bind(Uuid::from(device_id))
    .bind(&access.hash[..])
    .bind(access_expires_at)
    .bind(refresh_expires_at)
    .execute(&mut *conn)
    .await?;
    insert_refresh_token(conn, session_id, &refresh, refresh_expires_at).await?;

    Ok(TokenPair {
        session_id,
        access_token: access.token,
        access_expires_at,
        refresh_token: refresh.token,
        refresh_expires_at,
    })
}

async fn insert_refresh_token(
    conn: &mut PgConnection,
    session_id: SessionId,
    token: &IssuedToken,
    expires_at: DateTime<Utc>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, session_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&token.hash[..])
    .bind(Uuid::from(session_id))
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    session_id: Uuid,
    user_id: Uuid,
    token_expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    session_expires_at: DateTime<Utc>,
    session_revoked: bool,
    device_id: Uuid,
    device_revoked: bool,
    signing_public_key: Vec<u8>,
    user_active: bool,
}

/// The per-request device proof presented with a refresh (protocol 1.5).
#[derive(Debug)]
pub struct RefreshProof<'a> {
    pub proof: Option<RequestProof>,
    pub parts: &'a axum::http::request::Parts,
    pub body_hash: [u8; 32],
}

fn refresh_failure(reason: &'static str) -> AppError {
    metrics::counter!("cc_auth_failures_total", "reason" => reason).increment(1);
    AppError::unauthorized()
}

/// Rotate a refresh token. Single use: a token presented a second time
/// revokes its whole session (it leaked) and emits `session_revoked`.
pub async fn refresh(
    state: &AppState,
    presented: &SecretString,
    ip: Option<IpAddr>,
    proof: RefreshProof<'_>,
) -> AppResult<TokenPair> {
    let hash = crypto::presented_token_hash(TokenKind::Refresh, presented.expose_secret())
        .ok_or_else(|| refresh_failure("malformed_refresh_token"))?;

    let mut tx = state.db.begin().await?;
    // Row locks serialise concurrent refreshes of the same token: the loser
    // sees `used_at` and is treated as a replay.
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT rt.session_id, s.user_id, rt.expires_at AS token_expires_at, rt.used_at,
                s.expires_at AS session_expires_at, s.revoked_at IS NOT NULL AS session_revoked,
                s.device_id, d.revoked_at IS NOT NULL AS device_revoked, d.signing_public_key,
                u.status = 'active' AS user_active
           FROM refresh_tokens rt
           JOIN sessions s ON s.id = rt.session_id
           JOIN devices d ON d.id = s.device_id
           JOIN users u ON u.id = s.user_id
          WHERE rt.token_hash = $1
          FOR UPDATE OF rt, s",
    )
    .bind(&hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    let row = row.ok_or_else(|| refresh_failure("unknown_refresh_token"))?;
    let session_id = SessionId::from(row.session_id);
    let user_id = UserId::from(row.user_id);

    // A revoked device always learns it was revoked (it must create a new
    // identity); its sessions are already revoked, so reuse is moot.
    if row.device_revoked {
        return Err(AppError::device_revoked());
    }
    // Protocol 1.5: the refresh must come from the holder of the session's
    // device key. Checked before reuse detection, so a thief without the key
    // can neither refresh nor trigger a revocation of the victim's session.
    let proof_result = match &proof.proof {
        Some(p) => {
            middleware::verify_request_proof(
                &mut *tx,
                row.device_id.into(),
                &row.signing_public_key,
                proof.parts,
                &proof.body_hash,
                p,
            )
            .await
        }
        None if state.config.require_request_proof => Err(middleware::proof_error("missing")),
        None => {
            metrics::counter!("cc_request_proofs_total", "result" => "missing").increment(1);
            Ok(())
        }
    };
    if let Err(err) = proof_result {
        drop(tx);
        AuditEvent::new(AuditType::DeviceProofFailed)
            .user(user_id)
            .device(row.device_id.into())
            .ip(ip)
            .meta(serde_json::json!({ "endpoint": "refresh" }))
            .record(&state.db)
            .await?;
        return Err(err);
    }
    if row.used_at.is_some() {
        metrics::counter!("cc_auth_failures_total", "reason" => "refresh_token_reuse").increment(1);
        let newly_revoked = !row.session_revoked;
        if newly_revoked {
            revoke_session(&mut tx, session_id, "refresh_token_reuse").await?;
        }
        AuditEvent::new(AuditType::RefreshTokenReuse)
            .user(user_id)
            .device(row.device_id.into())
            .target(session_id)
            .ip(ip)
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        if newly_revoked {
            state
                .events
                .publish_user(user_id, ServerEvent::SessionRevoked { session_id })
                .await;
        }
        return Err(AppError::new(
            ErrorCode::RefreshTokenReused,
            "refresh token reuse detected; the session was revoked",
        ));
    }
    let now = Utc::now();
    if row.session_revoked
        || !row.user_active
        || row.token_expires_at <= now
        || row.session_expires_at <= now
    {
        return Err(refresh_failure("session_invalid"));
    }

    sqlx::query("UPDATE refresh_tokens SET used_at = now() WHERE token_hash = $1")
        .bind(&hash[..])
        .execute(&mut *tx)
        .await?;
    let access = crypto::issue_token(TokenKind::Access);
    let refresh = crypto::issue_token(TokenKind::Refresh);
    let access_expires_at = after(state.config.access_token_ttl);
    let refresh_expires_at = after(state.config.refresh_token_ttl);
    sqlx::query(
        "UPDATE sessions
            SET access_token_hash = $2, access_expires_at = $3, expires_at = $4,
                last_refreshed_at = now()
          WHERE id = $1",
    )
    .bind(row.session_id)
    .bind(&access.hash[..])
    .bind(access_expires_at)
    .bind(refresh_expires_at)
    .execute(&mut *tx)
    .await?;
    insert_refresh_token(&mut tx, session_id, &refresh, refresh_expires_at).await?;
    tx.commit().await?;

    Ok(TokenPair {
        session_id,
        access_token: access.token,
        access_expires_at,
        refresh_token: refresh.token,
        refresh_expires_at,
    })
}

/// Revoke one session. Returns whether it was live.
pub async fn revoke_session(
    conn: &mut PgConnection,
    session_id: SessionId,
    reason: &str,
) -> AppResult<bool> {
    let done = sqlx::query(
        "UPDATE sessions SET revoked_at = now(), revoke_reason = $2
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(session_id))
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Revoke every live session of `user_id` except `keep`. Returns revoked ids.
pub async fn revoke_user_sessions(
    conn: &mut PgConnection,
    user_id: UserId,
    keep: Option<SessionId>,
    reason: &str,
) -> AppResult<Vec<SessionId>> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE sessions SET revoked_at = now(), revoke_reason = $3
          WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)
          RETURNING id",
    )
    .bind(Uuid::from(user_id))
    .bind(keep.map(Uuid::from))
    .bind(reason)
    .fetch_all(conn)
    .await?;
    Ok(ids.into_iter().map(SessionId::from).collect())
}

/// Revoke every live session bound to `device_id`. Returns revoked ids.
pub async fn revoke_device_sessions(
    conn: &mut PgConnection,
    device_id: DeviceId,
    reason: &str,
) -> AppResult<Vec<SessionId>> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE sessions SET revoked_at = now(), revoke_reason = $2
          WHERE device_id = $1 AND revoked_at IS NULL
          RETURNING id",
    )
    .bind(Uuid::from(device_id))
    .bind(reason)
    .fetch_all(conn)
    .await?;
    Ok(ids.into_iter().map(SessionId::from).collect())
}

/// Purposes of single-use account tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountTokenPurpose {
    PasswordReset,
    EmailVerify,
}

impl AccountTokenPurpose {
    const fn as_str(self) -> &'static str {
        match self {
            AccountTokenPurpose::PasswordReset => "password_reset",
            AccountTokenPurpose::EmailVerify => "email_verify",
        }
    }
}

/// Issue a single-use account token; earlier unused tokens of the same
/// purpose are invalidated.
pub async fn issue_account_token(
    conn: &mut PgConnection,
    user_id: UserId,
    purpose: AccountTokenPurpose,
    ttl: Duration,
) -> AppResult<IssuedToken> {
    sqlx::query(
        "UPDATE account_tokens SET used_at = now()
          WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL",
    )
    .bind(Uuid::from(user_id))
    .bind(purpose.as_str())
    .execute(&mut *conn)
    .await?;
    let token = crypto::issue_token(TokenKind::Account);
    sqlx::query(
        "INSERT INTO account_tokens (token_hash, user_id, purpose, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&token.hash[..])
    .bind(Uuid::from(user_id))
    .bind(purpose.as_str())
    .bind(after(ttl))
    .execute(conn)
    .await?;
    Ok(token)
}

/// Check (without consuming) that an account token is live.
pub async fn check_account_token<'e>(
    db: impl sqlx::PgExecutor<'e>,
    presented: &SecretString,
    purpose: AccountTokenPurpose,
) -> AppResult<()> {
    let invalid = || AppError::bad_request("invalid or expired token");
    let hash = crypto::presented_token_hash(TokenKind::Account, presented.expose_secret())
        .ok_or_else(invalid)?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account_tokens
                         WHERE token_hash = $1 AND purpose = $2
                           AND used_at IS NULL AND expires_at > now())",
    )
    .bind(&hash[..])
    .bind(purpose.as_str())
    .fetch_one(db)
    .await?;
    if live {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Consume a single-use account token. Any failure is the same generic error.
pub async fn consume_account_token(
    conn: &mut PgConnection,
    presented: &SecretString,
    purpose: AccountTokenPurpose,
) -> AppResult<UserId> {
    let invalid = || AppError::bad_request("invalid or expired token");
    let hash = crypto::presented_token_hash(TokenKind::Account, presented.expose_secret())
        .ok_or_else(invalid)?;
    let user: Option<Uuid> = sqlx::query_scalar(
        "UPDATE account_tokens SET used_at = now()
          WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
          RETURNING user_id",
    )
    .bind(&hash[..])
    .bind(purpose.as_str())
    .fetch_optional(conn)
    .await?;
    user.map(UserId::from).ok_or_else(invalid)
}
