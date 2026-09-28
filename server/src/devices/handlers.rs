// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `/v1/devices/*` handlers (ADR-0004 authorization matrix).

use super::{device_info, list_device_infos, pending_requests, status_str, trust_request};
use crate::audit::{AuditEvent, AuditType};
use crate::auth::{sessions, AuthContext};
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::extract::{ApiJson, ApiJsonOrDefault, ApiPath, ClientIp};
use crate::mail::{self, templates};
use crate::state::AppState;
use crate::util::{short_text, validate_device_name};
use crate::vaults::access::{require_access_key, VaultAccess};
use crate::vaults::envelopes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cc_protocol::canonical::device_approval_message;
use cc_protocol::devices::{
    ApproveDeviceRequest, AttestDeviceRequest, CreateDeviceTrustRequest, DeviceInfo,
    DeviceRequestStatus, DeviceTrustRequest, ListDevicesResponse, RejectDeviceRequest,
    RevokeDeviceRequest, UpdateDeviceRequest,
};
use cc_protocol::envelopes::{KeyEnvelope, RecipientType};
use cc_protocol::events::ServerEvent;
use cc_protocol::limits::MAX_SIGNATURE_SKEW_SECONDS;
use cc_protocol::{DeviceId, DeviceRequestId, VaultId};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use uuid::Uuid;

/// `GET /v1/devices` → devices of the account + pending trust requests.
pub async fn list_devices(
    State(state): State<AppState>,
    auth: AuthContext,
) -> AppResult<Json<ListDevicesResponse>> {
    let devices = list_device_infos(&state.db, auth.user_id, auth.device_id).await?;
    let pending_requests = pending_requests(&state.db, auth.user_id, auth.device_id).await?;
    Ok(Json(ListDevicesResponse {
        devices,
        pending_requests,
    }))
}

/// `POST /v1/devices` → `201 DeviceTrustRequest`. The calling device asks to
/// be trusted. An empty `vault_ids` is expanded to every vault the account can
/// access; the stored/returned list is always explicit.
pub async fn create_trust_request(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJsonOrDefault(req): ApiJsonOrDefault<CreateDeviceTrustRequest>,
) -> AppResult<(StatusCode, Json<DeviceTrustRequest>)> {
    let accessible: Vec<Uuid> = sqlx::query_scalar(
        "SELECT v.id FROM vaults v
           JOIN vault_members m ON m.vault_id = v.id AND m.user_id = $1 AND m.revoked_at IS NULL
          WHERE v.state = 'active'
          ORDER BY v.id",
    )
    .bind(Uuid::from(auth.user_id))
    .fetch_all(&state.db)
    .await?;
    let accessible: BTreeSet<Uuid> = accessible.into_iter().collect();
    let requested: BTreeSet<Uuid> = if req.vault_ids.is_empty() {
        accessible.clone()
    } else {
        let set: BTreeSet<Uuid> = req.vault_ids.iter().map(|v| Uuid::from(*v)).collect();
        if !set.is_subset(&accessible) {
            return Err(AppError::not_found());
        }
        set
    };
    if requested.is_empty() {
        return Err(AppError::bad_request(
            "the account has no vaults to request access to",
        ));
    }

    let request_id = DeviceRequestId::new();
    let expires_at = Utc::now()
        + chrono::Duration::from_std(state.config.device_request_ttl)
            .unwrap_or(chrono::Duration::hours(24));
    let mut tx = state.db.begin().await?;
    // A new request supersedes older pending ones of the same device.
    sqlx::query(
        "UPDATE device_requests SET status = 'expired', decided_at = now()
          WHERE device_id = $1 AND status = 'pending'",
    )
    .bind(Uuid::from(auth.device_id))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO device_requests (id, user_id, device_id, status, expires_at)
         VALUES ($1, $2, $3, 'pending', $4)",
    )
    .bind(Uuid::from(request_id))
    .bind(Uuid::from(auth.user_id))
    .bind(Uuid::from(auth.device_id))
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    let vault_list: Vec<Uuid> = requested.into_iter().collect();
    sqlx::query(
        "INSERT INTO device_request_vaults (request_id, vault_id) SELECT $1, unnest($2::uuid[])",
    )
    .bind(Uuid::from(request_id))
    .bind(&vault_list)
    .execute(&mut *tx)
    .await?;
    AuditEvent::new(AuditType::DeviceTrustRequested)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(request_id)
        .ip(ip)
        .meta(serde_json::json!({ "vaults": vault_list.len() }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    state
        .events
        .publish_user(
            auth.user_id,
            ServerEvent::DeviceApprovalRequested {
                request_id,
                device_id: auth.device_id,
            },
        )
        .await;
    let dto = trust_request(&state.db, auth.user_id, request_id, auth.device_id).await?;
    Ok((StatusCode::CREATED, Json(dto)))
}

/// `PATCH /v1/devices/{device_id}` → `DeviceInfo` (rename a device of the
/// account).
pub async fn rename_device(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(device_id): ApiPath<DeviceId>,
    ApiJson(req): ApiJson<UpdateDeviceRequest>,
) -> AppResult<Json<DeviceInfo>> {
    let name = validate_device_name(&req.name)?;
    let mut tx = state.db.begin().await?;
    let updated = sqlx::query(
        "UPDATE devices SET name = $3 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(device_id))
    .bind(Uuid::from(auth.user_id))
    .bind(&name)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    AuditEvent::new(AuditType::DeviceRenamed)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(device_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        device_info(&state.db, auth.user_id, device_id, auth.device_id).await?,
    ))
}

#[derive(sqlx::FromRow)]
struct LockedRequest {
    device_id: Uuid,
    status: String,
    expires_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct KeysRow {
    encryption_public_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    revoked: bool,
}

async fn device_keys(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    device_id: Uuid,
) -> AppResult<Option<KeysRow>> {
    Ok(sqlx::query_as(
        "SELECT encryption_public_key, signing_public_key, revoked_at IS NOT NULL AS revoked
           FROM devices WHERE id = $1 AND user_id = $2
           FOR SHARE",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(conn)
    .await?)
}

/// Lock a trust request of the caller's account for `device_id` and check it
/// is pending and unexpired (expired → marked and `410`).
async fn lock_pending_request(
    conn: &mut sqlx::PgConnection,
    auth: &AuthContext,
    request_id: DeviceRequestId,
    device_id: DeviceId,
) -> AppResult<()> {
    let req: Option<LockedRequest> = sqlx::query_as(
        "SELECT device_id, status, expires_at FROM device_requests
          WHERE id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(Uuid::from(request_id))
    .bind(Uuid::from(auth.user_id))
    .fetch_optional(&mut *conn)
    .await?;
    let req = req.ok_or_else(AppError::not_found)?;
    if req.device_id != Uuid::from(device_id) {
        return Err(AppError::not_found());
    }
    if req.status != status_str(DeviceRequestStatus::Pending) {
        return Err(AppError::gone("the request is no longer pending"));
    }
    if req.expires_at <= Utc::now() {
        return Err(AppError::gone("the request has expired"));
    }
    Ok(())
}

/// `POST /v1/devices/{device_id}/approve` → `DeviceTrustRequest`.
///
/// Requires: the caller is trusted for every vault in `envelopes`, those
/// vaults are part of the pending, unexpired request, and `signature` is a
/// valid Ed25519 signature by the caller's registered signing key over
/// `canonical::device_approval_message` (strict verification).
pub async fn approve_device(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(device_id): ApiPath<DeviceId>,
    ApiJson(req): ApiJson<ApproveDeviceRequest>,
) -> AppResult<Json<DeviceTrustRequest>> {
    state
        .limits
        .proof_device
        .check(&Uuid::from(auth.device_id))?;
    if device_id == auth.device_id {
        return Err(AppError::forbidden("a device cannot approve itself"));
    }
    if req.envelopes.is_empty() {
        return Err(AppError::bad_request(
            "at least one vault envelope is required",
        ));
    }
    let mut vault_ids: Vec<VaultId> = Vec::with_capacity(req.envelopes.len());
    for ve in &req.envelopes {
        envelopes::validate(&ve.envelope, RecipientType::Device)?;
        if ve.envelope.recipient_id != Some(device_id.into()) {
            return Err(AppError::bad_request(
                "envelopes must be addressed to the approved device",
            ));
        }
        if vault_ids.contains(&ve.vault_id) {
            return Err(AppError::bad_request("duplicate vault in envelopes"));
        }
        vault_ids.push(ve.vault_id);
    }
    if (Utc::now().timestamp() - req.issued_at).abs() > MAX_SIGNATURE_SKEW_SECONDS {
        return Err(AppError::invalid_proof(
            "approval issued_at is outside the allowed clock skew",
        ));
    }

    let mut tx = state.db.begin().await?;
    lock_pending_request(&mut tx, &auth, req.request_id, device_id).await?;
    let requested: Vec<Uuid> =
        sqlx::query_scalar("SELECT vault_id FROM device_request_vaults WHERE request_id = $1")
            .bind(Uuid::from(req.request_id))
            .fetch_all(&mut *tx)
            .await?;
    if vault_ids
        .iter()
        .any(|v| !requested.contains(&Uuid::from(*v)))
    {
        return Err(AppError::bad_request(
            "every approved vault must be part of the request",
        ));
    }
    // T(v) of the approver for every approved vault.
    for v in &vault_ids {
        let access = VaultAccess::load(&mut *tx, &auth, *v).await?;
        access.require_trusted()?;
    }
    let new_device = device_keys(&mut tx, auth.user_id.into(), device_id.into())
        .await?
        .ok_or_else(AppError::not_found)?;
    if new_device.revoked {
        return Err(AppError::gone("the device has been revoked"));
    }
    let approver = device_keys(&mut tx, auth.user_id.into(), auth.device_id.into())
        .await?
        .ok_or_else(AppError::unauthorized)?;
    let (Ok(enc), Ok(sig)) = (
        <[u8; 32]>::try_from(new_device.encryption_public_key.as_slice()),
        <[u8; 32]>::try_from(new_device.signing_public_key.as_slice()),
    ) else {
        return Err(AppError::internal("stored device key has wrong length"));
    };
    let message = device_approval_message(
        req.request_id,
        auth.device_id,
        device_id,
        &enc,
        &sig,
        req.issued_at,
        &vault_ids,
    );
    if !crypto::verify_ed25519(
        &approver.signing_public_key,
        &message,
        req.signature.as_slice(),
    ) {
        drop(tx);
        metrics::counter!("cc_device_approvals_total", "result" => "bad_signature").increment(1);
        AuditEvent::new(AuditType::DeviceApprovalFailed)
            .user(auth.user_id)
            .device(auth.device_id)
            .target(device_id)
            .ip(ip)
            .record(&state.db)
            .await?;
        return Err(AppError::invalid_proof("invalid approval signature"));
    }

    for ve in &req.envelopes {
        envelopes::store(
            &mut tx,
            ve.vault_id,
            &ve.envelope,
            auth.device_id,
            "replaced",
        )
        .await?;
    }
    sqlx::query(
        "UPDATE device_requests
            SET status = 'approved', decided_at = now(), approved_by_device_id = $2
          WHERE id = $1",
    )
    .bind(Uuid::from(req.request_id))
    .bind(Uuid::from(auth.device_id))
    .execute(&mut *tx)
    .await?;
    AuditEvent::new(AuditType::DeviceApproved)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(device_id)
        .ip(ip)
        .meta(serde_json::json!({ "request_id": req.request_id, "vaults": vault_ids }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    metrics::counter!("cc_device_approvals_total", "result" => "approved").increment(1);
    state
        .events
        .publish_user(
            auth.user_id,
            ServerEvent::DeviceApproved {
                device_id,
                vault_ids: vault_ids.clone(),
            },
        )
        .await;
    Ok(Json(
        trust_request(&state.db, auth.user_id, req.request_id, auth.device_id).await?,
    ))
}

/// `POST /v1/devices/{device_id}/reject` → `204`. Any device trusted for at
/// least one requested vault may reject.
pub async fn reject_device(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(device_id): ApiPath<DeviceId>,
    ApiJson(req): ApiJson<RejectDeviceRequest>,
) -> AppResult<StatusCode> {
    let mut tx = state.db.begin().await?;
    lock_pending_request(&mut tx, &auth, req.request_id, device_id).await?;
    let trusted_any: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM device_request_vaults rv
              JOIN vaults v ON v.id = rv.vault_id AND v.state = 'active'
              JOIN vault_members m ON m.vault_id = v.id AND m.user_id = $2 AND m.revoked_at IS NULL
              JOIN vault_key_envelopes e ON e.vault_id = v.id AND e.recipient_type = 'device'
                                        AND e.recipient_id = $3 AND e.revoked_at IS NULL
             WHERE rv.request_id = $1)",
    )
    .bind(Uuid::from(req.request_id))
    .bind(Uuid::from(auth.user_id))
    .bind(Uuid::from(auth.device_id))
    .fetch_one(&mut *tx)
    .await?;
    if !trusted_any {
        return Err(AppError::device_not_trusted());
    }
    sqlx::query("UPDATE device_requests SET status = 'rejected', decided_at = now() WHERE id = $1")
        .bind(Uuid::from(req.request_id))
        .execute(&mut *tx)
        .await?;
    AuditEvent::new(AuditType::DeviceRejected)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(device_id)
        .ip(ip)
        .meta(serde_json::json!({ "request_id": req.request_id }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/devices/{self}/attest` → `KeyEnvelope`. The calling device proves
/// knowledge of the VRK via the vault access key (after unlocking with the
/// passphrase or Recovery Key) and stores its own device envelope.
pub async fn attest_device(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(device_id): ApiPath<DeviceId>,
    ApiJson(req): ApiJson<AttestDeviceRequest>,
) -> AppResult<Json<KeyEnvelope>> {
    if device_id != auth.device_id {
        return Err(AppError::forbidden("a device can only attest itself"));
    }
    envelopes::validate(&req.envelope, RecipientType::Device)?;
    if req.envelope.recipient_id != Some(auth.device_id.into()) {
        return Err(AppError::bad_request(
            "the envelope must be addressed to the calling device",
        ));
    }
    let access = VaultAccess::load(&state.db, &auth, req.vault_id).await?;
    require_access_key(
        &state,
        &auth,
        ip,
        &access,
        &req.vault_access_key,
        AuditType::DeviceAttestFailed,
    )
    .await?;

    let mut tx = state.db.begin().await?;
    // Serialise with a concurrent revoke of this device (revoke locks the row
    // FOR UPDATE and revokes its envelopes): never store an envelope for a
    // device that is being revoked.
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM devices WHERE id = $1 FOR SHARE")
            .bind(Uuid::from(auth.device_id))
            .fetch_one(&mut *tx)
            .await?;
    if revoked {
        return Err(AppError::device_revoked());
    }
    let stored = envelopes::store(
        &mut tx,
        req.vault_id,
        &req.envelope,
        auth.device_id,
        "replaced",
    )
    .await?;
    AuditEvent::new(AuditType::DeviceAttested)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(req.vault_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    metrics::counter!("cc_device_approvals_total", "result" => "attested").increment(1);
    state
        .events
        .publish_user(
            auth.user_id,
            ServerEvent::DeviceApproved {
                device_id,
                vault_ids: vec![req.vault_id],
            },
        )
        .await;
    Ok(Json(stored))
}

/// `POST /v1/devices/{device_id}/revoke` → `204`. Any active device of the
/// account may revoke any of its devices (ADR-0004). Revokes the device's
/// sessions, device envelopes and pending requests, closes its WebSockets.
pub async fn revoke_device(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(device_id): ApiPath<DeviceId>,
    ApiJsonOrDefault(req): ApiJsonOrDefault<RevokeDeviceRequest>,
) -> AppResult<StatusCode> {
    let reason = short_text(req.reason.as_deref(), 256);
    let mut tx = state.db.begin().await?;
    let found: Option<(String, bool)> = sqlx::query_as(
        "SELECT name, revoked_at IS NOT NULL FROM devices
          WHERE id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(Uuid::from(device_id))
    .bind(Uuid::from(auth.user_id))
    .fetch_optional(&mut *tx)
    .await?;
    let (device_name, already_revoked) = found.ok_or_else(AppError::not_found)?;
    if already_revoked {
        return Ok(StatusCode::NO_CONTENT);
    }
    sqlx::query("UPDATE devices SET revoked_at = now(), revoke_reason = $2 WHERE id = $1")
        .bind(Uuid::from(device_id))
        .bind(&reason)
        .execute(&mut *tx)
        .await?;
    let sessions = sessions::revoke_device_sessions(&mut tx, device_id, "device_revoked").await?;
    let envelopes_revoked = sqlx::query(
        "UPDATE vault_key_envelopes SET revoked_at = now(), revoke_reason = 'device_revoked'
          WHERE recipient_type = 'device' AND recipient_id = $1 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(device_id))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE device_requests SET status = 'rejected', decided_at = now()
          WHERE device_id = $1 AND status = 'pending'",
    )
    .bind(Uuid::from(device_id))
    .execute(&mut *tx)
    .await?;
    AuditEvent::new(AuditType::DeviceRevoked)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(device_id)
        .ip(ip)
        .meta(serde_json::json!({
            "sessions_revoked": sessions.len(),
            "envelopes_revoked": envelopes_revoked,
            "self": device_id == auth.device_id,
        }))
        .record(&mut *tx)
        .await?;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(Uuid::from(auth.user_id))
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;

    state
        .events
        .publish_user(auth.user_id, ServerEvent::DeviceRevoked { device_id })
        .await;
    mail::send_in_background(
        state.mailer.clone(),
        templates::device_revoked(&email, &device_name, state.config.public_url.as_deref()),
    );
    Ok(StatusCode::NO_CONTENT)
}
