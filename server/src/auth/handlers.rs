// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `/v1/auth/*` handlers and the account-recovery aliases.

use super::sessions::{self, AccountTokenPurpose};
use super::AuthContext;
use crate::audit::{AuditEvent, AuditType};
use crate::config::Limit;
use crate::devices::{self, protection, DeviceOutcome};
use crate::error::{is_unique_violation, spawn_in_request, AppError, AppResult};
use crate::extract::{ApiJson, ApiJsonOrDefault, ClientIp};
use crate::limiter::{Check, Key, Taken};
use crate::mail::{self, templates};
use crate::state::AppState;
use crate::util::{email_key, normalize_email, validate_account_password};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use cc_protocol::auth::{
    AccountInfo, AuthResponse, ChangePasswordRequest, ForgotPasswordRequest, LoginRequest,
    LogoutRequest, LogoutResponse, RefreshRequest, RegisterRequest, ResetPasswordRequest,
    TokenPair, VerifyEmailRequest,
};
use cc_protocol::devices::DeviceStatus;
use cc_protocol::events::ServerEvent;
use cc_protocol::{DeviceId, ErrorCode, UserId};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// `POST /v1/auth/register` → `201 AuthResponse`
pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> AppResult<(StatusCode, Json<AuthResponse>)> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    state.check_auth_ip(ip).await?;
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
    // A new account has no overrides yet.
    let quota = crate::limiter::effective_quotas(&state.config, &Default::default());
    devices::register_or_match(
        &mut tx,
        user_id,
        &req.device,
        req.device_proof.as_ref(),
        &quota,
    )
    .await?;
    // The device that creates the account is the owner's by definition: it
    // never starts in quarantine (device protection).
    sqlx::query("UPDATE devices SET quarantine_lifted_at = created_at WHERE id = $1")
        .bind(Uuid::from(device_id))
        .execute(&mut *tx)
        .await?;
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
    /// NULL for accounts linked to an enterprise identity (protocol 1.9):
    /// they never match a password, like an unknown user.
    password_hash: Option<String>,
    status: String,
    email_verified: bool,
}

/// `POST /v1/auth/login` → `AuthResponse`
///
/// Sign-in limits (security audit S2, TR-7/TR-8), all shared by replicas:
/// the client address (`auth_ip`), and *failed* attempts per e-mail and
/// client network (`login_email`) and per e-mail from all networks
/// (`login_email_total`). The e-mail budget is reserved before the password
/// check and given back on success, so a successful sign-in costs nothing and
/// concurrent attempts cannot overshoot. A known device of the account (a
/// valid, unused login proof) is never held back by the e-mail limits:
/// others' failures cannot lock the owner out.
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    state.check_auth_ip(ip).await?;
    // Normalise first: the limiter key is then bounded (≤ 254 bytes) and a
    // malformed address (e.g. with NUL, which PostgreSQL rejects) can never
    // match an account — it is treated like an unknown user.
    let email = normalize_email(&req.email).ok().map(|e| email_key(&e));
    devices::validate_registration(&req.device)?;
    if req.password.expose_secret().len() > cc_protocol::limits::MAX_ACCOUNT_PASSWORD_LEN {
        return Err(AppError::invalid_credentials());
    }

    let user: Option<LoginUserRow> =
        match &email {
            Some(email) => sqlx::query_as(
                "SELECT id, password_hash, status, email_verified_at IS NOT NULL AS email_verified
                   FROM users WHERE lower(email) = lower($1)",
            )
            .bind(email)
            .fetch_optional(&state.db)
            .await?,
            None => None,
        };
    let known_device = match (&user, &req.device_proof) {
        (Some(u), Some(proof)) => {
            devices::is_known_device(&state.db, u.id.into(), req.device.device_id, proof).await?
        }
        _ => false,
    };
    let mut reserved = Taken::default();
    if let Some(key) = &email {
        let checks = [
            Check::new(Limit::LoginEmail, Key::EmailNet(key, ip)),
            Check::new(Limit::LoginEmailTotal, Key::Email(key)),
        ];
        match state.rate.take(&state, None, &checks).await? {
            Ok(taken) => reserved = taken,
            Err(_) if known_device => {
                metrics::counter!("cc_auth_known_device_bypass_total").increment(1);
            }
            Err(refusal) => {
                if refusal.limit == Limit::LoginEmailTotal {
                    if let Some(u) = &user {
                        notify_failed_logins(&state, u.id.into(), ip);
                    }
                }
                return Err(refusal.into_error());
            }
        }
    }

    let ok = state
        .passwords
        .verify(
            &req.password,
            user.as_ref().and_then(|u| u.password_hash.as_deref()),
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
    // A successful sign-in does not spend the e-mail limits.
    state.rate.refund(&state.db, reserved).await?;
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
    let quota = state.rate.quotas(&state.db, &state.config, user_id).await?;
    let mut tx = state.db.begin().await?;
    let outcome = match devices::register_or_match(
        &mut tx,
        user_id,
        &req.device,
        req.device_proof.as_ref(),
        &quota,
    )
    .await
    {
        Ok(o) => o,
        Err(err) => {
            drop(tx);
            audit_device_quota(&state, user_id, &err);
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
        protection::on_device_created(&state, user_id, &req.device, ip).await;
    }
    Ok(Json(AuthResponse {
        user_id,
        device_id,
        device_status: DeviceStatus::Active,
        email_verified: user.email_verified,
        tokens,
    }))
}

/// Audit a device quota refusal (at most hourly per account and reason).
pub(crate) fn audit_device_quota(state: &AppState, user_id: UserId, err: &AppError) {
    use cc_protocol::quotas::reason;
    match err.detail("reason").and_then(|v| v.as_str()) {
        Some(reason::DEVICE_LIMIT) => state.rate.audit_quota(state, user_id, reason::DEVICE_LIMIT),
        Some(reason::DEVICE_DAILY_LIMIT) => {
            state
                .rate
                .audit_quota(state, user_id, reason::DEVICE_DAILY_LIMIT)
        }
        _ => {}
    }
}

/// TR-8: the per-e-mail limit of all networks refused a sign-in of an
/// existing account — tell the owner, at most once a UTC day (all replicas),
/// with a `limit_exceeded` audit event. Runs in the background.
fn notify_failed_logins(state: &AppState, user_id: UserId, ip: Option<IpAddr>) {
    let state = state.clone();
    spawn_in_request(async move {
        let result = async {
            let mut tx = state.db.begin().await?;
            let (count, _) = protection::bump(
                &mut tx,
                "failed_login_notice",
                Uuid::from(user_id),
                protection::Window::Day,
            )
            .await?;
            if count != 1 {
                return AppResult::Ok(());
            }
            AuditEvent::new(AuditType::LimitExceeded)
                .user(user_id)
                .ip(ip)
                .meta(serde_json::json!({ "limit": Limit::LoginEmailTotal.name() }))
                .record(&mut *tx)
                .await?;
            let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
                .bind(Uuid::from(user_id))
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            if state.mailer.delivers() {
                mail::send_in_background(
                    state.mailer.clone(),
                    templates::failed_logins(&email, state.config.public_url.as_deref()),
                );
            }
            AppResult::Ok(())
        }
        .await;
        if let Err(err) = result {
            tracing::warn!(code = ?err.code(), "failed-login notice failed");
        }
    });
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

/// `POST /v1/auth/logout` → `204`. `all_sessions` from a device in
/// quarantine (TR-6) keeps trusted devices signed in and answers `200`
/// [`LogoutResponse`] saying so.
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJsonOrDefault(req): ApiJsonOrDefault<LogoutRequest>,
) -> AppResult<Response> {
    let mut tx = state.db.begin().await?;
    let quarantine = if req.all_sessions {
        protection::quarantine_of(&mut *tx, &state.config.device_protection, auth.device_id).await?
    } else {
        None
    };
    let revoked = if req.all_sessions && quarantine.is_some() {
        sessions::revoke_untrusted_sessions(
            &mut tx,
            auth.user_id,
            auth.device_id,
            None,
            "logout_all",
        )
        .await?
    } else if req.all_sessions {
        sessions::revoke_user_sessions(&mut tx, auth.user_id, None, "logout_all").await?
    } else if sessions::revoke_session(&mut tx, auth.session_id, "logout").await? {
        vec![auth.session_id]
    } else {
        vec![]
    };
    let trusted_kept = match quarantine {
        Some(_) => trusted_devices_besides(&mut tx, auth.user_id, auth.device_id).await?,
        None => 0,
    };
    AuditEvent::new(AuditType::Logout)
        .user(auth.user_id)
        .device(auth.device_id)
        .ip(ip)
        .meta(serde_json::json!({
            "all_sessions": req.all_sessions,
            "sessions": revoked.len(),
            "quarantine": quarantine.is_some(),
        }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    let count = revoked.len();
    for session_id in revoked {
        state
            .events
            .publish_user(auth.user_id, ServerEvent::SessionRevoked { session_id })
            .await;
    }
    Ok(match quarantine {
        Some(until) => Json(LogoutResponse {
            sessions_revoked: u32::try_from(count).unwrap_or(u32::MAX),
            trusted_devices_kept: trusted_kept,
            quarantine_until: Some(until),
        })
        .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    })
}

/// Active trusted devices of `user_id` other than `device_id`.
async fn trusted_devices_besides(
    conn: &mut sqlx::PgConnection,
    user_id: UserId,
    device_id: DeviceId,
) -> AppResult<u32> {
    let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM devices d
          WHERE d.user_id = $1 AND d.id <> $2 AND d.revoked_at IS NULL AND {}",
        protection::trusted_sql("d.id")
    )))
    .bind(Uuid::from(user_id))
    .bind(Uuid::from(device_id))
    .fetch_one(conn)
    .await?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
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
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    start_password_reset(state, ip, req, false).await
}

/// `POST /v1/recovery/account/start` → `202` (always). Account access only —
/// never vault access (ADR-0004).
pub async fn recovery_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ForgotPasswordRequest>,
) -> AppResult<StatusCode> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    start_password_reset(state, ip, req, true).await
}

/// TR-8: requests are limited per e-mail *and client network*
/// (`recovery_email`), keyed on the input so a `429` reveals nothing about
/// account existence; others' requests from other networks never block the
/// owner. The per-e-mail ceiling of all networks (`recovery_email_total`)
/// only stops *mails* (the answer stays `202`), and requests from a network
/// the owner signed in from recently are exempt from it.
async fn start_password_reset(
    state: AppState,
    ip: Option<IpAddr>,
    req: ForgotPasswordRequest,
    recovery: bool,
) -> AppResult<StatusCode> {
    state.check_auth_ip(ip).await?;
    // Malformed input still gets the same 202 (no account can match it).
    let Ok(email) = normalize_email(&req.email) else {
        return Ok(StatusCode::ACCEPTED);
    };
    let key = email_key(&email);
    state
        .rate
        .check(
            &state,
            None,
            &[Check::new(Limit::RecoveryEmail, Key::EmailNet(&key, ip))],
        )
        .await?;
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
    let total = [Check::new(Limit::RecoveryEmailTotal, Key::Email(email_key))];
    if state.rate.take(state, None, &total).await?.is_err()
        && !known_network(state, user_id, ip).await?
    {
        metrics::counter!("cc_recovery_mail_suppressed_total").increment(1);
        state.rate.audit(
            state,
            user_id.into(),
            Limit::RecoveryEmailTotal.name(),
            true,
        );
        return Ok(());
    }
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

/// Whether the account signed in from the network of `ip` (IPv4 /24, IPv6
/// /64) in the last 90 days, according to the audit trail.
async fn known_network(state: &AppState, user_id: Uuid, ip: Option<IpAddr>) -> AppResult<bool> {
    let Some(ip) = ip else {
        return Ok(false);
    };
    let net = crate::ratelimit::subnet_key(ip);
    let seen: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT ip_address FROM audit_events
          WHERE user_id = $1 AND event_type IN ('login', 'register')
            AND occurred_at > now() - interval '90 days'
          ORDER BY occurred_at DESC LIMIT 200",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(seen
        .iter()
        .flatten()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .any(|a| crate::ratelimit::subnet_key(a) == net))
}

/// `POST /v1/auth/password/reset` → `204`
pub async fn reset_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ResetPasswordRequest>,
) -> AppResult<StatusCode> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    complete_password_reset(&state, ip, req, false).await
}

/// `POST /v1/recovery/account/confirm` → `204`
pub async fn recovery_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ResetPasswordRequest>,
) -> AppResult<StatusCode> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    complete_password_reset(&state, ip, req, true).await
}

/// Sets a new account password and revokes every session and every other
/// pending reset/verification token (TR-12). With device protection, devices
/// that never unlocked a vault are revoked too (TR-11) and the owner gets a
/// mail listing them with a "This wasn't me" link (TR-13). Vault ciphertext,
/// envelopes and the trust of trusted devices are untouched.
async fn complete_password_reset(
    state: &AppState,
    ip: Option<IpAddr>,
    req: ResetPasswordRequest,
    recovery: bool,
) -> AppResult<StatusCode> {
    state.check_auth_ip(ip).await?;
    validate_account_password(&req.new_password)?;
    // Cheap token check first so garbage tokens never cost an Argon2 hash.
    sessions::check_account_token(&state.db, &req.token, AccountTokenPurpose::PasswordReset)
        .await?;
    let password_hash = state.passwords.hash(&req.new_password).await?;
    let prot = &state.config.device_protection;

    let mut tx = state.db.begin().await?;
    let user_id =
        sessions::consume_account_token(&mut tx, &req.token, AccountTokenPurpose::PasswordReset)
            .await?;
    // A reset proves control of the mailbox, so it also verifies the email.
    let email: String = sqlx::query_scalar(
        "UPDATE users
            SET password_hash = $2, password_changed_at = now(), updated_at = now(),
                email_verified_at = COALESCE(email_verified_at, now())
          WHERE id = $1
          RETURNING email",
    )
    .bind(Uuid::from(user_id))
    .bind(&password_hash)
    .fetch_one(&mut *tx)
    .await?;
    let mut revoked_devices: Vec<(Uuid, String)> = Vec::new();
    let mut revoked = Vec::new();
    if prot.enabled {
        let never_trusted: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, name FROM devices
              WHERE user_id = $1 AND revoked_at IS NULL AND first_trusted_at IS NULL
              ORDER BY created_at FOR UPDATE",
        )
        .bind(Uuid::from(user_id))
        .fetch_all(&mut *tx)
        .await?;
        for (id, name) in never_trusted {
            let r = devices::revoke_locked(
                &mut tx,
                id.into(),
                Some("password_reset"),
                "password_reset",
            )
            .await?;
            revoked.extend(r.sessions);
            revoked_devices.push((id, name));
        }
    }
    revoked.extend(sessions::revoke_user_sessions(&mut tx, user_id, None, "password_reset").await?);
    let tokens_invalidated = sessions::invalidate_account_tokens(&mut tx, user_id, true).await?;
    let deny_token = if prot.enabled && state.mailer.delivers() {
        Some(protection::issue_deny_token(&mut tx, user_id, None).await?)
    } else {
        None
    };
    AuditEvent::new(if recovery {
        AuditType::AccountRecoveryCompleted
    } else {
        AuditType::PasswordReset
    })
    .user(user_id)
    .ip(ip)
    .meta(serde_json::json!({
        "sessions_revoked": revoked.len(),
        "devices_revoked": revoked_devices.len(),
        "tokens_invalidated": tokens_invalidated,
    }))
    .record(&mut *tx)
    .await?;
    tx.commit().await?;

    if recovery {
        metrics::counter!("cc_recovery_attempts_total", "kind" => "account_confirm").increment(1);
    }
    for (id, _) in &revoked_devices {
        state
            .events
            .publish_user(
                user_id,
                ServerEvent::DeviceRevoked {
                    device_id: (*id).into(),
                },
            )
            .await;
    }
    for session_id in revoked {
        state
            .events
            .publish_user(user_id, ServerEvent::SessionRevoked { session_id })
            .await;
    }
    if let Some(token) = deny_token {
        let names: Vec<String> = revoked_devices.into_iter().map(|(_, n)| n).collect();
        mail::send_in_background(
            state.mailer.clone(),
            templates::password_reset_completed(
                &email,
                &names,
                token.token.expose_secret(),
                state.config.public_url.as_deref(),
            ),
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/password/change` → `204`. Other sessions and pending reset
/// tokens are revoked; from a device in quarantine (TR-7) sessions of trusted
/// devices are kept and the owner gets a "This wasn't me" mail.
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> AppResult<StatusCode> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    state
        .limits
        .proof_device
        .check(&Uuid::from(auth.device_id))?;
    state
        .rate
        .account(&state, Limit::AccountSecurity, auth.user_id)
        .await?;
    validate_account_password(&req.new_password)?;
    let (current_hash, email): (Option<String>, String) =
        sqlx::query_as("SELECT password_hash, email FROM users WHERE id = $1")
            .bind(Uuid::from(auth.user_id))
            .fetch_one(&state.db)
            .await?;
    if !state
        .passwords
        .verify(&req.current_password, current_hash.as_deref())
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
    let quarantine =
        protection::quarantine_of(&mut *tx, &state.config.device_protection, auth.device_id)
            .await?;
    let revoked = if quarantine.is_some() {
        sessions::revoke_untrusted_sessions(
            &mut tx,
            auth.user_id,
            auth.device_id,
            Some(auth.session_id),
            "password_changed",
        )
        .await?
    } else {
        sessions::revoke_user_sessions(
            &mut tx,
            auth.user_id,
            Some(auth.session_id),
            "password_changed",
        )
        .await?
    };
    sessions::invalidate_account_tokens(&mut tx, auth.user_id, false).await?;
    let notice = match quarantine {
        Some(_) => {
            let name: String = sqlx::query_scalar("SELECT name FROM devices WHERE id = $1")
                .bind(Uuid::from(auth.device_id))
                .fetch_one(&mut *tx)
                .await?;
            let token =
                protection::issue_deny_token(&mut tx, auth.user_id, Some(auth.device_id)).await?;
            templates::password_changed_new_device(
                &email,
                &name,
                token.token.expose_secret(),
                state.config.public_url.as_deref(),
            )
        }
        None => templates::password_changed(&email, state.config.public_url.as_deref()),
    };
    AuditEvent::new(AuditType::PasswordChanged)
        .user(auth.user_id)
        .device(auth.device_id)
        .ip(ip)
        .meta(serde_json::json!({
            "sessions_revoked": revoked.len(),
            "quarantine": quarantine.is_some(),
        }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    for session_id in revoked {
        state
            .events
            .publish_user(auth.user_id, ServerEvent::SessionRevoked { session_id })
            .await;
    }
    mail::send_in_background(state.mailer.clone(), notice);
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/email/verify` → `204`
pub async fn verify_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<VerifyEmailRequest>,
) -> AppResult<StatusCode> {
    if state.config.auth.is_enterprise() {
        return Err(crate::enterprise::enterprise_auth_required());
    }
    state.check_auth_ip(ip).await?;
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
