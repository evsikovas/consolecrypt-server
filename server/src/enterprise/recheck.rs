// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Re-checking users at the IdP / directory (ТР-6): employees disabled there
//! lose sync access within about `CC_AUTH_RECHECK_MINUTES`.
//!
//! * On refresh-token rotation, at most every `RECHECK_MINUTES` per identity
//!   ([`due`] / [`run`]), and by a background sweep ([`spawn`]) for accounts
//!   with live sessions, so revocation does not wait for the next refresh.
//! * OIDC: refresh grant with the stored (sealed) IdP refresh token;
//!   `invalid_grant`, a different `sub` or a lost required claim → refused.
//!   LDAP: lookup by `objectGUID` with the service account; disabled,
//!   deleted or outside the required group → refused.
//! * Refused: every session of the account is revoked (reason
//!   `account_disabled`) and refresh answers `403 account_disabled`.
//! * IdP/directory unreachable: sessions keep working until
//!   `RECHECK_GRACE_HOURS` after the last successful check, then refresh
//!   answers `503 idp_unavailable` (nothing is revoked).
//! * A session of an account without an identity of the configured source
//!   (password sessions from before the switch) cannot be re-checked: its
//!   refresh answers `403 enterprise_auth_required` (sign in again).

use super::{oidc::UpstreamError, token_context, Enterprise, Provider};
use crate::audit::{AuditEvent, AuditType};
use crate::auth::sessions;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use cc_protocol::events::ServerEvent;
use cc_protocol::{ErrorCode, UserId};
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

/// Advisory-lock key of the sweep ("ccrechk").
const SWEEP_LOCK_KEY: i64 = 0x63_63_72_65_63_68_6b;
const SWEEP_BATCH: i64 = 50;

/// Revocation reason stored on sessions ended by a re-check.
pub const REVOKE_REASON: &str = "account_disabled";

pub fn account_disabled() -> AppError {
    AppError::new(
        ErrorCode::AccountDisabled,
        "access disabled by the administrator",
    )
}

fn idp_unavailable() -> AppError {
    AppError::Api {
        code: ErrorCode::IdpUnavailable,
        message: "the identity provider is unreachable; try again later".into(),
        details: None,
        retry_after_seconds: Some(60),
    }
}

/// Whether a refresh of `user_id`'s session needs a re-check first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    No,
    Yes,
}

#[derive(sqlx::FromRow)]
struct IdentityRow {
    subject: String,
    checked_at: DateTime<Utc>,
    upstream_refresh_token: Option<Vec<u8>>,
}

fn span(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

/// Decide inside the refresh transaction (cheap, no network).
pub async fn due(
    conn: &mut sqlx::PgConnection,
    state: &AppState,
    user_id: UserId,
) -> AppResult<Due> {
    let Some(ent) = &state.enterprise else {
        return Ok(Due::No);
    };
    let checked: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT checked_at FROM account_identities
          WHERE account_id = $1 AND provider = $2 AND issuer = $3",
    )
    .bind(Uuid::from(user_id))
    .bind(ent.kind().as_str())
    .bind(ent.issuer())
    .fetch_optional(conn)
    .await?;
    match checked {
        None => Err(super::enterprise_auth_required()),
        Some(at) if Utc::now() - at < span(state.config.auth.recheck_interval) => Ok(Due::No),
        Some(_) => Ok(Due::Yes),
    }
}

/// Result of asking the IdP/directory about one identity.
#[derive(Debug)]
enum Verdict {
    Ok {
        new_refresh: Option<Vec<u8>>,
    },
    Refused(&'static str),
    Unavailable(&'static str),
    /// No upstream refresh token to check with (IdP issued none).
    Unverifiable,
}

async fn ask(ent: &Enterprise, state: &AppState, row: &IdentityRow) -> Verdict {
    match &ent.provider {
        Provider::Ldap(l) => match l.lookup_subject(&row.subject).await {
            Ok(None) => Verdict::Refused("deleted"),
            Ok(Some(u)) if u.disabled => Verdict::Refused("disabled"),
            Ok(Some(u)) if !u.in_group => Verdict::Refused("group_required"),
            Ok(Some(_)) => Verdict::Ok { new_refresh: None },
            Err(super::ldap::Unavailable(why)) => Verdict::Unavailable(why),
        },
        Provider::Oidc(o) => {
            let tb = ent.token_box.as_ref().expect("OIDC has a token box");
            let ctx = token_context(ent.kind(), ent.issuer(), &row.subject);
            let Some(token) = row
                .upstream_refresh_token
                .as_deref()
                .and_then(|sealed| tb.open(&ctx, sealed))
            else {
                return Verdict::Unverifiable;
            };
            match o.refresh(&token).await {
                Err(UpstreamError::InvalidGrant) => Verdict::Refused("invalid_grant"),
                Err(UpstreamError::Unavailable(why)) => Verdict::Unavailable(why),
                Ok(resp) => {
                    if let Some(id_token) = &resp.id_token {
                        match o.validate_id_token(id_token, None).await {
                            Ok(claims) => {
                                if super::claim_str(&claims, "sub") != Some(row.subject.as_str()) {
                                    return Verdict::Refused("subject_changed");
                                }
                                if o.check_policy(&state.config.auth, &claims).is_err() {
                                    return Verdict::Refused("policy");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(reason = e.reason(), "refreshed ID token rejected");
                                return Verdict::Unavailable("invalid ID token from the IdP");
                            }
                        }
                    }
                    Verdict::Ok {
                        new_refresh: resp.refresh_token.map(|t| tb.seal(&ctx, t.expose_secret())),
                    }
                }
            }
        }
    }
}

/// Outcome of [`run`] for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Fresh enough, checked ok, or another replica is checking right now.
    Ok,
    /// Unreachable but within the grace window.
    Grace,
    /// Refused: all sessions revoked.
    Revoked,
    /// Unreachable beyond the grace window.
    Unavailable,
    /// Cannot be verified (no upstream token) beyond the grace window.
    ReauthRequired,
}

/// Re-check `user_id` now if due. Holds the identity row lock (SKIP LOCKED:
/// concurrent refreshes/replicas do not ask the IdP twice).
pub async fn run(state: &AppState, user_id: UserId) -> AppResult<Outcome> {
    let Some(ent) = state.enterprise.clone() else {
        return Ok(Outcome::Ok);
    };
    let auth = &state.config.auth;
    let mut tx = state.db.begin().await?;
    let row: Option<IdentityRow> = sqlx::query_as(
        "SELECT subject, checked_at, upstream_refresh_token FROM account_identities
          WHERE account_id = $1 AND provider = $2 AND issuer = $3
          FOR UPDATE SKIP LOCKED",
    )
    .bind(Uuid::from(user_id))
    .bind(ent.kind().as_str())
    .bind(ent.issuer())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        // Locked by a concurrent check (or unlinked meanwhile).
        return Ok(Outcome::Ok);
    };
    let now = Utc::now();
    if now - row.checked_at < span(auth.recheck_interval) {
        return Ok(Outcome::Ok);
    }
    let verdict = ask(&ent, state, &row).await;
    let past_grace = now - row.checked_at > span(auth.recheck_interval + auth.recheck_grace);
    let provider = ent.kind().as_str();
    match verdict {
        Verdict::Ok { new_refresh } => {
            sqlx::query(
                "UPDATE account_identities
                    SET checked_at = now(), check_unavailable_since = NULL,
                        upstream_refresh_token = COALESCE($4, upstream_refresh_token)
                  WHERE account_id = $1 AND provider = $2 AND issuer = $3",
            )
            .bind(Uuid::from(user_id))
            .bind(provider)
            .bind(ent.issuer())
            .bind(new_refresh)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(Outcome::Ok)
        }
        Verdict::Refused(reason) => {
            let revoked =
                sessions::revoke_user_sessions(&mut tx, user_id, None, REVOKE_REASON).await?;
            // Nothing left to re-check with; a new sign-in stores a new one.
            sqlx::query(
                "UPDATE account_identities SET upstream_refresh_token = NULL
                  WHERE account_id = $1 AND provider = $2 AND issuer = $3",
            )
            .bind(Uuid::from(user_id))
            .bind(provider)
            .bind(ent.issuer())
            .execute(&mut *tx)
            .await?;
            AuditEvent::new(AuditType::EnterpriseAccessRevoked)
                .user(user_id)
                .meta(serde_json::json!({
                    "provider": provider,
                    "reason": reason,
                    "sessions_revoked": revoked.len(),
                }))
                .record(&mut *tx)
                .await?;
            tx.commit().await?;
            tracing::warn!(
                user_id = %Uuid::from(user_id),
                provider,
                reason,
                sessions = revoked.len(),
                "enterprise re-check refused the user; sessions revoked"
            );
            metrics::counter!("cc_enterprise_rechecks_total", "result" => "revoked").increment(1);
            for session_id in revoked {
                state
                    .events
                    .publish_user(user_id, ServerEvent::SessionRevoked { session_id })
                    .await;
            }
            Ok(Outcome::Revoked)
        }
        Verdict::Unavailable(why) => {
            sqlx::query(
                "UPDATE account_identities
                    SET check_unavailable_since = COALESCE(check_unavailable_since, now())
                  WHERE account_id = $1 AND provider = $2 AND issuer = $3",
            )
            .bind(Uuid::from(user_id))
            .bind(provider)
            .bind(ent.issuer())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            tracing::warn!(
                provider,
                why,
                past_grace,
                "enterprise re-check: identity source unavailable"
            );
            metrics::counter!("cc_enterprise_rechecks_total", "result" => "unavailable")
                .increment(1);
            if let Err(e) = super::record_status(&state.db, ent.kind(), false, why).await {
                tracing::debug!(
                    failure = crate::error::database_error_kind(&e),
                    "status not recorded"
                );
            }
            Ok(if past_grace {
                Outcome::Unavailable
            } else {
                Outcome::Grace
            })
        }
        Verdict::Unverifiable => {
            drop(tx);
            tracing::warn!(
                provider,
                "enterprise re-check impossible: the IdP issued no refresh token (request \
                 offline access); the user must sign in again after the grace period"
            );
            Ok(if past_grace {
                Outcome::ReauthRequired
            } else {
                Outcome::Grace
            })
        }
    }
}

/// Map a re-check outcome to the refresh response.
pub fn outcome_error(outcome: Outcome) -> Option<AppError> {
    match outcome {
        Outcome::Ok | Outcome::Grace => None,
        Outcome::Revoked => Some(account_disabled()),
        Outcome::Unavailable => Some(idp_unavailable()),
        Outcome::ReauthRequired => Some(super::enterprise_auth_required()),
    }
}

/// One sweep: re-check identities with live sessions whose last check is
/// older than the interval. Returns how many were checked.
pub async fn sweep_once(state: &AppState) -> anyhow::Result<usize> {
    let Some(ent) = state.enterprise.clone() else {
        return Ok(0);
    };
    let mut conn = state.db.acquire().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(SWEEP_LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        return Ok(0);
    }
    let result = async {
        let users: Vec<Uuid> = sqlx::query_scalar(
            "SELECT i.account_id FROM account_identities i
              WHERE i.provider = $1 AND i.issuer = $2
                AND i.checked_at < now() - make_interval(secs => $3)
                AND EXISTS (SELECT 1 FROM sessions s
                             WHERE s.user_id = i.account_id AND s.revoked_at IS NULL
                               AND s.expires_at > now())
              ORDER BY i.checked_at
              LIMIT $4",
        )
        .bind(ent.kind().as_str())
        .bind(ent.issuer())
        .bind(state.config.auth.recheck_interval.as_secs_f64())
        .bind(SWEEP_BATCH)
        .fetch_all(&mut *conn)
        .await?;
        let n = users.len();
        for u in users {
            if let Err(e) = run(state, UserId::from(u)).await {
                tracing::warn!(code = ?e.code(), "enterprise re-check failed");
            }
        }
        anyhow::Ok(n)
    }
    .await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(SWEEP_LOCK_KEY)
        .execute(&mut *conn)
        .await;
    result
}

/// Background sweep every minute (enterprise mode only).
pub fn spawn(state: AppState) {
    if state.enterprise.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            match sweep_once(&state).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(identities = n, "enterprise re-check sweep"),
                Err(e) => tracing::warn!(
                    failure = crate::error::internal_error_kind(&e),
                    "enterprise re-check sweep failed"
                ),
            }
        }
    });
}
