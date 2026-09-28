// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `/v1/auth/*` handlers and the account-recovery aliases.

use super::sessions::{self, AccountTokenPurpose};
use super::AuthContext;
use crate::audit::{AuditEvent, AuditType};
use crate::devices::{self, DeviceOutcome};
use crate::error::{is_unique_violation, spawn_in_request, AppError, AppResult};
use crate::extract::{ApiJson, ApiJsonOrDefault, ClientIp};
use crate::mail::{self, templates};
use crate::state::AppState;
use crate::util::{email_key, normalize_email, validate_account_password};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cc_protocol::auth::{
    AccountInfo, AuthResponse, ChangePasswordRequest, ForgotPasswordRequest, LoginRequest,
    LogoutRequest, RefreshRequest, RegisterRequest, ResetPasswordRequest, TokenPair,
    VerifyEmailRequest,
};
use cc_protocol::devices::DeviceStatus;
use cc_protocol::events::ServerEvent;
use cc_protocol::{ErrorCode, UserId};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// `POST /v1/auth/register` → `201 AuthResponse`
pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> AppResult<(StatusCode, Json<AuthResponse>)> {
    state.limits.check_auth_ip(ip)?;
    if !state.config.registration_open {
        return Err(AppError::forbidden("registration is closed on this server"));
    }
    let email = normalize_email(&req.email)?;
    validate_account_password(&req.password)?;
    devices::validate_registration(&req.device)?;
    let password_hash = state.passwords.hash(&req.password).await?;

    let user_id = UserId::new();
    let device_id = req.device.device_id;
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)")
        .bind(Uuid::from(user_id))
        .bind(&email)
        .bind(&password_hash)
        .execute(&mut *tx)
        .await;
    match inserted {
        Err(err) if is_unique_violation(&err) => {
            return Err(AppError::already_exists(
                "email",
                "an account with this email already exists",
            ))
        }
        other => {
            other?;
        }
    }
    devices::register_or_match(&mut tx, user_id, &req.device, req.device_proof.as_ref()).await?;
    let tokens = sessions::create_session(&mut tx, &state.config, user_id, device_id).await?;
    AuditEvent::new(AuditType::Register)
        .user(user_id)
        .device(device_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    AuditEvent::new(AuditType::DeviceAdded)
        .user(user_id)
        .device(device_id)
        .target(device_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    let verify_token = if state.mailer.delivers() {
        Some(
            sessions::issue_account_token(
                &mut tx,
                user_id,
                AccountTokenPurpose::EmailVerify,
                state.config.email_verify_ttl,
            )
            .await?,
        )
    } else {
        None
    };
    tx.commit().await?;

    if let Some(token) = verify_token {
        mail::send_in_background(
            state.mailer.clone(),
            templates::verify_email(
                &email,
                token.token.expose_secret(),
                state.config.public_url.as_deref(),
            ),
        );
    }
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user_id,
            device_id,
            device_status: DeviceStatus::Active,
            email_verified: false,
            tokens,
        }),
    ))
}

#[derive(sqlx::FromRow)]
struct LoginUserRow {
    id: Uuid,
    password_hash: String,
    status: String,
    email_verified: bool,
}

/// `POST /v1/auth/login` → `AuthResponse`
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    state.limits.check_auth_ip(ip)?;
    // Normalise first: the limiter key is then bounded (≤ 254 bytes) and a
    // malformed address (e.g. with NUL, which PostgreSQL rejects) can never
    // match an account — it is treated like an unknown user.
    let email = normalize_email(&req.email).ok();
    if let Some(e) = &email {
        state.limits.login_email.check(&email_key(e))?;
    }
    devices::validate_registration(&req.device)?;
    if req.password.expose_secret().len() > cc_protocol::limits::MAX_ACCOUNT_PASSWORD_LEN {
        return Err(AppError::invalid_credentials());
    }

    let user: Option<LoginUserRow> =
        match email {
            Some(email) => sqlx::query_as(
                "SELECT id, password_hash, status, email_verified_at IS NOT NULL AS email_verified
                   FROM users WHERE lower(email) = lower($1)",
            )
            .bind(email)
            .fetch_optional(&state.db)
            .await?,
            None => None,
        };

    let ok = state
        .passwords
        .verify(
            &req.password,
            user.as_ref().map(|u| u.password_hash.as_str()),
        )
        .await?;
    let user = match user {
        Some(u) if ok => u,
        other => {
            metrics::counter!("cc_auth_failures_total", "reason" => "invalid_credentials")
                .increment(1);
            if let Some(u) = other {
                AuditEvent::new(AuditType::LoginFailed)
                    .user(u.id.into())
                    .ip(ip)
                    .record(&state.db)
                    .await?;
            }
            return Err(AppError::invalid_credentials());
        }
    };
    let user_id = UserId::from(user.id);
    if user.status != "active" {
        return Err(AppError::forbidden("account disabled"));
    }
    if state.config.require_email_verification && !user.email_verified {
        return Err(AppError::new(
            ErrorCode::EmailNotVerified,
            "email address not verified",
        ));
    }

    let device_id = req.device.device_id;
    let mut tx = state.db.begin().await?;
    let outcome =
        match devices::register_or_match(&mut tx, user_id, &req.device, req.device_proof.as_ref())
            .await
        {
            Ok(o) => o,
            Err(err) => {
                drop(tx);
                if err.code() == ErrorCode::InvalidProof {
                    // Correct password but no proof for this device: suspicious.
                    AuditEvent::new(AuditType::DeviceProofFailed)
                        .user(user_id)
                        .device(device_id)
                        .ip(ip)
                        .record(&state.db)
                        .await?;
                }
                return Err(err);
            }
        };
    let tokens = sessions::create_session(&mut tx, &state.config, user_id, device_id).await?;
    AuditEvent::new(AuditType::Login)
        .user(user_id)
        .device(device_id)
        .ip(ip)
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

    if outcome == DeviceOutcome::Created {
        state
            .events
            .publish_user(user_id, ServerEvent::DeviceAdded { device_id })
            .await;
    }
    Ok(Json(AuthResponse {
        user_id,
        device_id,
        device_status: DeviceStatus::Active,
        email_verified: user.email_verified,
        tokens,
    }))
}

/// `POST /v1/auth/refresh` → `TokenPair`
///
/// Reads the raw body: the protocol 1.5 device proof signs its SHA-256.
pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    req: axum::extract::Request,
) -> AppResult<Json<TokenPair>> {
    state.limits.check_auth_ip(ip)?;
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, crate::AUTH_BODY_LIMIT)
        .await
        .map_err(|_| AppError::payload_too_large("request body too large"))?;
    let refresh_req: RefreshRequest = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::bad_request("request body does not match RefreshRequest"))?;
    let proof = match parts.headers.get(cc_protocol::version::HEADER_DEVICE_PROOF) {
        None => None,
        Some(v) => Some(
            v.to_str()
                .ok()
                .and_then(cc_protocol::devices::RequestProof::decode)
                .ok_or_else(|| super::middleware::proof_error("malformed"))?,
        ),
    };
    let proof = sessions::RefreshProof {
        proof,
        parts: &parts,
        body_hash: crate::crypto::sha256(&bytes),
    };
    sessions::refresh(&state, &refresh_req.refresh_token, ip, proof)
        .await
        .map(Json)
}

/// `POST /v1/auth/logout` → `204`
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJsonOrDefault(req): ApiJsonOrDefault<LogoutRequest>,
) -> AppResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    let revoked = if req.all_sessions {
        sessions::revoke_user_sessions(&mut tx, auth.user_id, None, "logout_all").await?
    } else if sessions::revoke_session(&mut tx, auth.session_id, "logout").await? {
        vec![auth.session_id]
    } else {
        vec![]
    };
    AuditEvent::new(AuditType::Logout)
        .user(auth.user_id)
        .device(auth.device_id)
        .ip(ip)
        .meta(serde_json::json!({ "all_sessions": req.all_sessions, "sessions": revoked.len() }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    for session_id in revoked {
        state
            .events
            .publish_user(auth.user_id, ServerEvent::SessionRevoked { session_id })
            .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct MeRow {
    email: String,
    email_verified: bool,
    created_at: DateTime<Utc>,
}

/// `GET /v1/auth/me` → `AccountInfo`
pub async fn me(State(state): State<AppState>, auth: AuthContext) -> AppResult<Json<AccountInfo>> {
    let row: MeRow = sqlx::query_as(
        "SELECT email, email_verified_at IS NOT NULL AS email_verified, created_at
           FROM users WHERE id = $1",
    )
    .bind(Uuid::from(auth.user_id))
    .fetch_one(&state.db)
    .await?;
    Ok(Json(AccountInfo {
        user_id: auth.user_id,
        email: row.email,
        email_verified: row.email_verified,
        created_at: row.created_at,
        current_device_id: auth.device_id,
        current_session_id: auth.session_id,
    }))
}

/// `POST /v1/auth/password/forgot` → `202` (always).
pub async fn forgot_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ForgotPasswordRequest>,
) -> AppResult<StatusCode> {
    start_password_reset(state, ip, req, false)
}

/// `POST /v1/recovery/account/start` → `202` (always). Account access only —
/// never vault access (ADR-0004).
pub async fn recovery_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ForgotPasswordRequest>,
) -> AppResult<StatusCode> {
    start_password_reset(state, ip, req, true)
}

fn start_password_reset(
    state: AppState,
    ip: Option<IpAddr>,
    req: ForgotPasswordRequest,
    recovery: bool,
) -> AppResult<StatusCode> {
    state.limits.check_auth_ip(ip)?;
    // Malformed input still gets the same 202 (no account can match it).
    let Ok(email) = normalize_email(&req.email) else {
        return Ok(StatusCode::ACCEPTED);
    };
    let key = email_key(&email);
    // Keyed on the *input*, so a 429 reveals nothing about account existence.
    state.limits.recovery_email.check(&key)?;
    metrics::counter!("cc_recovery_attempts_total", "kind" => if recovery { "account_start" } else { "password_forgot" })
        .increment(1);
    // The rest runs in the background so response time does not depend on
    // whether the account exists.
    spawn_in_request(async move {
        if let Err(err) = issue_password_reset(&state, &key, ip, recovery).await {
            // Details may contain the recipient address (PII): debug only.
            tracing::warn!("password reset issuance failed");
            tracing::debug!(error = %err, "password reset issuance failure details");
        }
    });
    Ok(StatusCode::ACCEPTED)
}

async fn issue_password_reset(
    state: &AppState,
    email_key: &str,
    ip: Option<IpAddr>,
    recovery: bool,
) -> AppResult<()> {
    let user: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, email FROM users WHERE lower(email) = $1 AND status = 'active'")
            .bind(email_key)
            .fetch_optional(&state.db)
            .await?;
    let Some((user_id, email)) = user else {
        return Ok(());
    };
    let mut tx = state.db.begin().await?;
    let token = sessions::issue_account_token(
        &mut tx,
        user_id.into(),
        AccountTokenPurpose::PasswordReset,
        state.config.password_reset_ttl,
    )
    .await?;
    AuditEvent::new(if recovery {
        AuditType::AccountRecoveryStarted
    } else {
        AuditType::PasswordResetRequested
    })
    .user(user_id.into())
    .ip(ip)
    .record(&mut *tx)
    .await?;
    tx.commit().await?;
    state
        .mailer
        .send(templates::password_reset(
            &email,
            token.token.expose_secret(),
            recovery,
            state.config.public_url.as_deref(),
        ))
        .await?;
    Ok(())
}

/// `POST /v1/auth/password/reset` → `204`
pub async fn reset_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ResetPasswordRequest>,
) -> AppResult<StatusCode> {
    complete_password_reset(&state, ip, req, false).await
}

/// `POST /v1/recovery/account/confirm` → `204`
pub async fn recovery_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ResetPasswordRequest>,
) -> AppResult<StatusCode> {
    complete_password_reset(&state, ip, req, true).await
}

/// Sets a new account password and revokes every session. Vault ciphertext,
/// envelopes and device trust are untouched.
async fn complete_password_reset(
    state: &AppState,
    ip: Option<IpAddr>,
    req: ResetPasswordRequest,
    recovery: bool,
) -> AppResult<StatusCode> {
    state.limits.check_auth_ip(ip)?;
    validate_account_password(&req.new_password)?;
    // Cheap token check first so garbage tokens never cost an Argon2 hash.
    sessions::check_account_token(&state.db, &req.token, AccountTokenPurpose::PasswordReset)
        .await?;
    let password_hash = state.passwords.hash(&req.new_password).await?;

    let mut tx = state.db.begin().await?;
    let user_id =
        sessions::consume_account_token(&mut tx, &req.token, AccountTokenPurpose::PasswordReset)
            .await?;
    // A reset proves control of the mailbox, so it also verifies the email.
    sqlx::query(
        "UPDATE users
            SET password_hash = $2, password_changed_at = now(), updated_at = now(),
                email_verified_at = COALESCE(email_verified_at, now())
          WHERE id = $1",
    )
    .bind(Uuid::from(user_id))
    .bind(&password_hash)
    .execute(&mut *tx)
    .await?;
    let revoked = sessions::revoke_user_sessions(&mut tx, user_id, None, "password_reset").await?;
    AuditEvent::new(if recovery {
        AuditType::AccountRecoveryCompleted
    } else {
        AuditType::PasswordReset
    })
    .user(user_id)
    .ip(ip)
    .meta(serde_json::json!({ "sessions_revoked": revoked.len() }))
    .record(&mut *tx)
    .await?;
    tx.commit().await?;

    if recovery {
        metrics::counter!("cc_recovery_attempts_total", "kind" => "account_confirm").increment(1);
    }
    for session_id in revoked {
        state
            .events
            .publish_user(user_id, ServerEvent::SessionRevoked { session_id })
            .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/password/change` → `204`. Other sessions are revoked.
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> AppResult<StatusCode> {
    state
        .limits
        .proof_device
        .check(&Uuid::from(auth.device_id))?;
    validate_account_password(&req.new_password)?;
    let (current_hash, email): (String, String) =
        sqlx::query_as("SELECT password_hash, email FROM users WHERE id = $1")
            .bind(Uuid::from(auth.user_id))
            .fetch_one(&state.db)
            .await?;
    if !state
        .passwords
        .verify(&req.current_password, Some(&current_hash))
        .await?
    {
        metrics::counter!("cc_auth_failures_total", "reason" => "change_password").increment(1);
        return Err(AppError::invalid_credentials());
    }
    let new_hash = state.passwords.hash(&req.new_password).await?;

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now()
          WHERE id = $1",
    )
    .bind(Uuid::from(auth.user_id))
    .bind(&new_hash)
    .execute(&mut *tx)
    .await?;
    let revoked = sessions::revoke_user_sessions(
        &mut tx,
        auth.user_id,
        Some(auth.session_id),
        "password_changed",
    )
    .await?;
    AuditEvent::new(AuditType::PasswordChanged)
        .user(auth.user_id)
        .device(auth.device_id)
        .ip(ip)
        .meta(serde_json::json!({ "sessions_revoked": revoked.len() }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    for session_id in revoked {
        state
            .events
            .publish_user(auth.user_id, ServerEvent::SessionRevoked { session_id })
            .await;
    }
    mail::send_in_background(
        state.mailer.clone(),
        templates::password_changed(&email, state.config.public_url.as_deref()),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/email/verify` → `204`
pub async fn verify_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<VerifyEmailRequest>,
) -> AppResult<StatusCode> {
    state.limits.check_auth_ip(ip)?;
    let mut tx = state.db.begin().await?;
    let user_id =
        sessions::consume_account_token(&mut tx, &req.token, AccountTokenPurpose::EmailVerify)
            .await?;
    sqlx::query(
        "UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()), updated_at = now()
          WHERE id = $1",
    )
    .bind(Uuid::from(user_id))
    .execute(&mut *tx)
    .await?;
    AuditEvent::new(AuditType::EmailVerified)
        .user(user_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
