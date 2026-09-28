// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Principal **A** (ADR-0004): a valid access token of an active device whose
//! session is not revoked. Re-checked against the database on every request.

use crate::crypto::{self, TokenKind};
use crate::error::AppError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use cc_protocol::{DeviceId, SessionId, UserId};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct AuthContext {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub email_verified: bool,
    /// SHA-256 of the presented access token (lets long-lived connections
    /// notice when that token expires or is rotated).
    pub access_token_hash: [u8; 32],
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("session_id", &self.session_id)
            .field("email_verified", &self.email_verified)
            .finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct AuthRow {
    session_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    access_expires_at: DateTime<Utc>,
    session_revoked: bool,
    device_revoked: bool,
    signing_public_key: Vec<u8>,
    user_active: bool,
    email_verified: bool,
}

fn fail(reason: &'static str) -> AppError {
    metrics::counter!("cc_auth_failures_total", "reason" => reason).increment(1);
    AppError::unauthorized()
}

/// Extract the bearer token from an `Authorization` header value.
pub fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Resolve the bearer token of a request to its principal (principal A):
/// one indexed query; revoked device → 403, anything else → 401. Returns the
/// device's signing key too (for request proofs).
pub(crate) async fn lookup(
    state: &AppState,
    parts: &Parts,
) -> Result<(AuthContext, Vec<u8>), AppError> {
    let token = bearer_token(parts).ok_or_else(|| fail("missing_token"))?;
    let hash = crypto::presented_token_hash(TokenKind::Access, token)
        .ok_or_else(|| fail("malformed_token"))?;

    let db_timer = crate::db::DbTimer::start("auth_lookup");
    let row: Option<AuthRow> = sqlx::query_as(
        "SELECT s.id AS session_id, s.user_id, s.device_id, s.access_expires_at,
                s.revoked_at IS NOT NULL AS session_revoked,
                d.revoked_at IS NOT NULL AS device_revoked,
                d.signing_public_key,
                u.status = 'active' AS user_active,
                u.email_verified_at IS NOT NULL AS email_verified
           FROM sessions s
           JOIN devices d ON d.id = s.device_id
           JOIN users u ON u.id = s.user_id
          WHERE s.access_token_hash = $1",
    )
    .bind(&hash[..])
    .fetch_optional(&state.db)
    .await?;
    drop(db_timer);

    let row = row.ok_or_else(|| fail("unknown_token"))?;
    if row.device_revoked {
        metrics::counter!("cc_auth_failures_total", "reason" => "device_revoked").increment(1);
        return Err(AppError::device_revoked());
    }
    if row.session_revoked {
        return Err(fail("session_revoked"));
    }
    if !row.user_active {
        return Err(fail("user_disabled"));
    }
    if row.access_expires_at <= Utc::now() {
        return Err(fail("token_expired"));
    }

    let ctx = AuthContext {
        user_id: row.user_id.into(),
        device_id: row.device_id.into(),
        session_id: row.session_id.into(),
        email_verified: row.email_verified,
        access_token_hash: hash,
    };
    let span = tracing::Span::current();
    span.record("user_id", tracing::field::display(ctx.user_id));
    span.record("device_id", tracing::field::display(ctx.device_id));

    if state.should_touch_device(ctx.device_id) {
        sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
            .bind(row.device_id)
            .execute(&state.db)
            .await?;
    }
    Ok((ctx, row.signing_public_key))
}

/// Handlers receive the principal established by
/// [`crate::auth::middleware::authenticate`] (which also verified the
/// request proof). A handler outside that middleware is a wiring bug.
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> Result<Self, AppError> {
        parts
            .extensions
            .get::<AuthContext>()
            .copied()
            .ok_or_else(|| {
                tracing::error!("authenticated handler reached without the auth middleware");
                AppError::internal("authentication middleware missing")
            })
    }
}
