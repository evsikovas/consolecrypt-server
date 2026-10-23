// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Identity → account (ТР-3) and the session hand-out shared by OIDC and
//! LDAP sign-in.
//!
//! * An account is found by its identity `(provider, issuer, subject)`; the
//!   email is only an attribute (a changed email follows the identity).
//! * A password account with the same email is linked on its first
//!   enterprise sign-in only if its domain is in `CC_AUTH_ALLOWED_DOMAINS`
//!   and it has no identity yet; its account password is removed and its old
//!   password sessions are signed out. An account linked to another identity
//!   is never taken over (`identity_conflict`).
//! * Otherwise a new account is created (`CC_AUTH_AUTO_CREATE`).

use super::{Refusal, VerifiedIdentity};
use crate::audit::{AuditEvent, AuditType};
use crate::auth::sessions;
use crate::devices::{self, protection, DeviceOutcome};
use crate::error::{is_unique_violation, AppError, AppResult};
use crate::state::AppState;
use crate::util::normalize_email;
use cc_protocol::auth::AuthResponse;
use cc_protocol::devices::{DeviceProof, DeviceRegistration, DeviceStatus};
use cc_protocol::events::ServerEvent;
use cc_protocol::{ErrorCode, UserId};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Existing,
    Linked,
    Created,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedAccount {
    pub user_id: UserId,
    pub how: Resolution,
}

/// Record a refused sign-in (audit + log line with the reason).
pub async fn audit_refusal(
    state: &AppState,
    user: Option<UserId>,
    ip: Option<IpAddr>,
    method: &'static str,
    err: &AppError,
) {
    let reason = super::error_reason(err);
    let code = crate::util::enum_str(&err.code());
    tracing::warn!(method, code = %code, reason, user_id = ?user.map(Uuid::from), "enterprise sign-in refused");
    metrics::counter!("cc_enterprise_logins_total", "method" => method, "result" => "refused")
        .increment(1);
    let mut ev = AuditEvent::new(AuditType::LoginFailed)
        .ip(ip)
        .meta(serde_json::json!({ "method": method, "code": code, "reason": reason }));
    if let Some(u) = user {
        ev = ev.user(u);
    }
    if let Err(e) = ev.record(&state.db).await {
        tracing::warn!(code = ?e.code(), "cannot record a refused sign-in");
    }
}

/// Audit a refusal and turn it into the API error.
pub async fn refuse(
    state: &AppState,
    user: Option<UserId>,
    ip: Option<IpAddr>,
    method: &'static str,
    refusal: Refusal,
) -> AppError {
    let err: AppError = refusal.into();
    audit_refusal(state, user, ip, method, &err).await;
    err
}

#[derive(sqlx::FromRow)]
struct IdentityRow {
    account_id: Uuid,
    status: String,
    email: Option<String>,
}

#[derive(sqlx::FromRow)]
struct EmailRow {
    id: Uuid,
    status: String,
    has_identity: bool,
}

/// Find, link or create the account of `ident` (ТР-3).
pub async fn resolve(
    state: &AppState,
    ident: &VerifiedIdentity,
    ip: Option<IpAddr>,
    upstream_refresh: Option<&[u8]>,
) -> AppResult<ResolvedAccount> {
    match resolve_once(state, ident, ip, upstream_refresh).await {
        // Two first sign-ins raced on the same email/identity: the second
        // attempt sees the winner's rows.
        Err(AppError::Db(e)) if is_unique_violation(&e) => {
            resolve_once(state, ident, ip, upstream_refresh).await
        }
        other => other,
    }
}

async fn resolve_once(
    state: &AppState,
    ident: &VerifiedIdentity,
    ip: Option<IpAddr>,
    upstream_refresh: Option<&[u8]>,
) -> AppResult<ResolvedAccount> {
    let auth = &state.config.auth;
    let email = ident.email.as_deref().and_then(|e| normalize_email(e).ok());
    if !auth.allowed_domains.is_empty() && !email.as_deref().is_some_and(|e| auth.domain_allowed(e))
    {
        return Err(refuse(
            state,
            None,
            ip,
            ident.provider.as_str(),
            Refusal::DomainNotAllowed,
        )
        .await);
    }
    let provider = ident.provider.as_str();
    let mut tx = state.db.begin().await?;

    // 1. Known identity.
    let known: Option<IdentityRow> = sqlx::query_as(
        "SELECT i.account_id, u.status, i.email
           FROM account_identities i JOIN users u ON u.id = i.account_id
          WHERE i.provider = $1 AND i.issuer = $2 AND i.subject = $3
          FOR UPDATE OF i",
    )
    .bind(provider)
    .bind(&ident.issuer)
    .bind(&ident.subject)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = known {
        let user_id = UserId::from(row.account_id);
        if row.status != "active" {
            drop(tx);
            return Err(refuse(state, Some(user_id), ip, provider, Refusal::AccountDisabled).await);
        }
        sqlx::query(
            "UPDATE account_identities
                SET email = COALESCE($4, email), last_login_at = now(), checked_at = now(),
                    check_unavailable_since = NULL,
                    upstream_refresh_token = COALESCE($5, upstream_refresh_token)
              WHERE provider = $1 AND issuer = $2 AND subject = $3",
        )
        .bind(provider)
        .bind(&ident.issuer)
        .bind(&ident.subject)
        .bind(email.as_deref())
        .bind(upstream_refresh)
        .execute(&mut *tx)
        .await?;
        // The email follows the directory unless another account owns it.
        if let Some(new) = email.as_deref() {
            if row.email.as_deref().map(str::to_lowercase) != Some(new.to_lowercase()) {
                let taken: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1) AND id <> $2)",
                )
                .bind(new)
                .bind(row.account_id)
                .fetch_one(&mut *tx)
                .await?;
                if !taken {
                    sqlx::query(
                        "UPDATE users SET email = $2, email_verified_at = COALESCE(email_verified_at, now()),
                                updated_at = now()
                          WHERE id = $1 AND lower(email) <> lower($2)",
                    )
                    .bind(row.account_id)
                    .bind(new)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        clear_password(&mut tx, user_id).await?;
        tx.commit().await?;
        return Ok(ResolvedAccount {
            user_id,
            how: Resolution::Existing,
        });
    }

    // 2. Unknown identity: an account with the same email?
    let Some(email) = email else {
        drop(tx);
        return Err(refuse(state, None, ip, provider, Refusal::EmailMissing).await);
    };
    let existing: Option<EmailRow> = sqlx::query_as(
        "SELECT u.id, u.status,
                EXISTS (SELECT 1 FROM account_identities i WHERE i.account_id = u.id) AS has_identity
           FROM users u WHERE lower(u.email) = lower($1)
           FOR UPDATE OF u",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        let user_id = UserId::from(row.id);
        let refusal = if row.has_identity {
            Some(Refusal::IdentityConflict("linked_to_other_identity"))
        } else if auth.allowed_domains.is_empty() {
            // Without a domain list the IdP is not authoritative for the
            // address: link with `admin identity link` instead.
            Some(Refusal::IdentityConflict("link_requires_allowed_domain"))
        } else if !ident.email_verified {
            Some(Refusal::IdentityConflict("email_not_verified"))
        } else if row.status != "active" {
            Some(Refusal::AccountDisabled)
        } else {
            None
        };
        if let Some(r) = refusal {
            drop(tx);
            return Err(refuse(state, Some(user_id), ip, provider, r).await);
        }
        insert_identity(&mut tx, user_id, ident, Some(&email), upstream_refresh).await?;
        clear_password(&mut tx, user_id).await?;
        sqlx::query(
            "UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), updated_at = now()
              WHERE id = $1",
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
        // Sessions opened with the old account password end here.
        let revoked =
            sessions::revoke_user_sessions(&mut tx, user_id, None, "identity_linked").await?;
        AuditEvent::new(AuditType::IdentityLinked)
            .user(user_id)
            .ip(ip)
            .meta(serde_json::json!({
                "provider": provider,
                "via": "first_sign_in",
                "sessions_revoked": revoked.len(),
            }))
            .record(&mut *tx)
            .await?;
        tx.commit().await?;
        tracing::info!(user_id = %Uuid::from(user_id), provider, "existing account linked to its enterprise identity");
        for session_id in revoked {
            state
                .events
                .publish_user(user_id, ServerEvent::SessionRevoked { session_id })
                .await;
        }
        return Ok(ResolvedAccount {
            user_id,
            how: Resolution::Linked,
        });
    }

    // 3. New account.
    if !auth.auto_create {
        drop(tx);
        return Err(refuse(state, None, ip, provider, Refusal::NotProvisioned).await);
    }
    let user_id = UserId::new();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified_at) VALUES ($1, $2, NULL, now())",
    )
    .bind(Uuid::from(user_id))
    .bind(&email)
    .execute(&mut *tx)
    .await?;
    insert_identity(&mut tx, user_id, ident, Some(&email), upstream_refresh).await?;
    AuditEvent::new(AuditType::Register)
        .user(user_id)
        .ip(ip)
        .meta(serde_json::json!({ "method": provider }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(user_id = %Uuid::from(user_id), provider, "account created by enterprise sign-in");
    Ok(ResolvedAccount {
        user_id,
        how: Resolution::Created,
    })
}

async fn insert_identity(
    conn: &mut sqlx::PgConnection,
    user_id: UserId,
    ident: &VerifiedIdentity,
    email: Option<&str>,
    upstream_refresh: Option<&[u8]>,
) -> AppResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO account_identities
             (account_id, provider, issuer, subject, email, last_login_at, checked_at,
              upstream_refresh_token)
         VALUES ($1, $2, $3, $4, $5, now(), now(), $6)",
    )
    .bind(Uuid::from(user_id))
    .bind(ident.provider.as_str())
    .bind(&ident.issuer)
    .bind(&ident.subject)
    .bind(email)
    .bind(upstream_refresh)
    .execute(conn)
    .await;
    match inserted {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn clear_password(conn: &mut sqlx::PgConnection, user_id: UserId) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET password_hash = NULL, updated_at = now()
          WHERE id = $1 AND password_hash IS NOT NULL",
    )
    .bind(Uuid::from(user_id))
    .execute(conn)
    .await?;
    Ok(())
}

/// Register or match the device and open a session — the same device rules
/// as password login (protocol 1.4 proofs, 1.7 device protection).
pub async fn complete_login(
    state: &AppState,
    ip: Option<IpAddr>,
    user_id: UserId,
    device: &DeviceRegistration,
    device_proof: Option<&DeviceProof>,
    method: &'static str,
) -> AppResult<AuthResponse> {
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(Uuid::from(user_id))
        .fetch_optional(&state.db)
        .await?;
    if status.as_deref() != Some("active") {
        return Err(refuse(state, Some(user_id), ip, method, Refusal::AccountDisabled).await);
    }
    let device_id = device.device_id;
    let quota = state.rate.quotas(&state.db, &state.config, user_id).await?;
    let mut tx = state.db.begin().await?;
    let outcome =
        match devices::register_or_match(&mut tx, user_id, device, device_proof, &quota).await {
            Ok(o) => o,
            Err(err) => {
                drop(tx);
                crate::auth::handlers::audit_device_quota(state, user_id, &err);
                if err.code() == ErrorCode::InvalidProof {
                    AuditEvent::new(AuditType::DeviceProofFailed)
                        .user(user_id)
                        .device(device_id)
                        .ip(ip)
                        .meta(serde_json::json!({ "method": method }))
                        .record(&state.db)
                        .await?;
                }
                return Err(err);
            }
        };
    // The device that opens a brand-new account is the owner's by
    // definition: like at registration it never starts in quarantine.
    let first_device = outcome == DeviceOutcome::Created && {
        let others: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM devices WHERE user_id = $1 AND id <> $2)",
        )
        .bind(Uuid::from(user_id))
        .bind(Uuid::from(device_id))
        .fetch_one(&mut *tx)
        .await?;
        !others
    };
    if first_device {
        sqlx::query("UPDATE devices SET quarantine_lifted_at = created_at WHERE id = $1")
            .bind(Uuid::from(device_id))
            .execute(&mut *tx)
            .await?;
    }
    let tokens = sessions::create_session(&mut tx, &state.config, user_id, device_id).await?;
    AuditEvent::new(AuditType::Login)
        .user(user_id)
        .device(device_id)
        .ip(ip)
        .meta(serde_json::json!({ "method": method }))
        .record(&mut *tx)
        .await?;
    if outcome == DeviceOutcome::Created {
        AuditEvent::new(AuditType::DeviceAdded)
            .user(user_id)
            .device(device_id)
            .target(device_id)
            .ip(ip)
            .record(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(
        user_id = %Uuid::from(user_id),
        device_id = %Uuid::from(device_id),
        method,
        new_device = outcome == DeviceOutcome::Created,
        "enterprise sign-in"
    );
    metrics::counter!("cc_enterprise_logins_total", "method" => method, "result" => "ok")
        .increment(1);

    if outcome == DeviceOutcome::Created {
        state
            .events
            .publish_user(user_id, ServerEvent::DeviceAdded { device_id })
            .await;
        if !first_device {
            protection::on_device_created(state, user_id, device, ip).await;
        }
    }
    Ok(AuthResponse {
        user_id,
        device_id,
        device_status: DeviceStatus::Active,
        // The IdP/directory vouches for the address.
        email_verified: true,
        tokens,
    })
}
