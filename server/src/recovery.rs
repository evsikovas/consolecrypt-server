// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Vault recovery (`/v1/recovery/vault/*`, ADR-0004). The server validates
//! authorization and stores opaque envelopes; it never decrypts anything.
//! Account recovery (`/v1/recovery/account/*`) lives in `auth::handlers` and
//! never grants vault access.

use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::extract::{ApiJson, ApiQuery, ClientIp};
use crate::state::AppState;
use crate::util::enum_str;
use crate::vaults::access::require_trusted_with_key;
use crate::vaults::envelopes;
use crate::vaults::VaultAccess;
use axum::extract::State;
use axum::Json;
use cc_protocol::devices::{ApprovalVaultCommitment, DeviceApprovalRecord};
use cc_protocol::envelopes::{KeyEnvelope, RecipientType};
use cc_protocol::events::ServerEvent;
use cc_protocol::recovery::{RecoveryMaterialQuery, ReplaceEnvelopeRequest, VaultRecoveryMaterial};
use std::net::IpAddr;
use uuid::Uuid;

/// `GET /v1/recovery/vault/envelope?vault_id` — any active device of a
/// member; for a device not trusted for the vault metered by device
/// protection (`429 envelope_rate_limited`).
pub async fn vault_material(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiQuery(q): ApiQuery<RecoveryMaterialQuery>,
) -> AppResult<Json<VaultRecoveryMaterial>> {
    let access = VaultAccess::load(&state.db, &auth, q.vault_id).await?;
    let password_envelope =
        envelopes::live_for(&state.db, q.vault_id, RecipientType::Password, None).await?;
    let recovery_envelope =
        envelopes::live_for(&state.db, q.vault_id, RecipientType::Recovery, None).await?;
    let device_envelope = envelopes::live_for(
        &state.db,
        q.vault_id,
        RecipientType::Device,
        Some(auth.device_id.into()),
    )
    .await?;
    if !access.trusted && (password_envelope.is_some() || recovery_envelope.is_some()) {
        crate::devices::protection::meter_unlock_material(
            &state,
            &auth,
            ip,
            q.vault_id,
            "recovery_material",
        )
        .await?;
    }
    let device_approval = match &device_envelope {
        Some(_) => approval_v2_for(&state.db, auth.device_id, q.vault_id).await?,
        None => None,
    };
    metrics::counter!("cc_recovery_attempts_total", "kind" => "vault_material").increment(1);
    Ok(Json(VaultRecoveryMaterial {
        vault_id: q.vault_id,
        password_envelope,
        recovery_envelope,
        device_envelope,
        device_approval,
    }))
}

#[derive(sqlx::FromRow)]
struct ApprovalV2Row {
    request_id: Uuid,
    approver_device_id: Uuid,
    issued_at: i64,
    vault_commitments: sqlx::types::Json<Vec<ApprovalVaultCommitment>>,
    signature: Vec<u8>,
}

/// The newest v2 approval of `device_id` that covers `vault_id` (protocol
/// 1.11), exactly as the approver signed it.
async fn approval_v2_for(
    db: &sqlx::PgPool,
    device_id: cc_protocol::DeviceId,
    vault_id: cc_protocol::VaultId,
) -> AppResult<Option<DeviceApprovalRecord>> {
    let row: Option<ApprovalV2Row> = sqlx::query_as(
        "SELECT a.request_id, a.approver_device_id, a.issued_at, a.vault_commitments, a.signature
           FROM device_approvals_v2 a
           JOIN device_requests r ON r.id = a.request_id AND r.status = 'approved'
          WHERE a.device_id = $1
            AND a.vault_commitments @> jsonb_build_array(jsonb_build_object('vault_id', $2::text))
          ORDER BY a.created_at DESC
          LIMIT 1",
    )
    .bind(Uuid::from(device_id))
    .bind(vault_id.to_string())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| DeviceApprovalRecord {
        request_id: r.request_id.into(),
        approver_device_id: r.approver_device_id.into(),
        issued_at: r.issued_at,
        vault_commitments: r.vault_commitments.0,
        signature_v2: r.signature.into(),
    }))
}

/// `POST /v1/recovery/vault/password-envelope/replace` → `KeyEnvelope`.
pub async fn replace_password_envelope(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ReplaceEnvelopeRequest>,
) -> AppResult<Json<KeyEnvelope>> {
    replace(&state, &auth, ip, req, RecipientType::Password).await
}

/// `POST /v1/recovery/vault/recovery-envelope/replace` → `KeyEnvelope`.
pub async fn replace_recovery_envelope(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<ReplaceEnvelopeRequest>,
) -> AppResult<Json<KeyEnvelope>> {
    replace(&state, &auth, ip, req, RecipientType::Recovery).await
}

/// T(V) + K(V); the old envelope of the same type is revoked atomically with
/// the insert of the new one. Emits `recovery_changed`.
async fn replace(
    state: &AppState,
    auth: &AuthContext,
    ip: Option<IpAddr>,
    req: ReplaceEnvelopeRequest,
    recipient_type: RecipientType,
) -> AppResult<Json<KeyEnvelope>> {
    // Password change, recovery kit re-issue, envelope replacement (S2).
    state
        .rate
        .account(state, crate::config::Limit::AccountSecurity, auth.user_id)
        .await?;
    envelopes::validate(&req.envelope, recipient_type)?;
    let access =
        require_trusted_with_key(state, auth, ip, req.vault_id, &req.vault_access_key).await?;
    // Members reach a Team Vault's key only through their user envelopes; a
    // password or recovery envelope would let any member plant a key there.
    if access.is_team {
        return Err(AppError::bad_request(
            "team vaults have no password or recovery envelopes",
        ));
    }

    let mut tx = state.db.begin().await?;
    // Serialise concurrent replacements of the same vault.
    sqlx::query("SELECT 1 FROM vaults WHERE id = $1 FOR UPDATE")
        .bind(Uuid::from(req.vault_id))
        .execute(&mut *tx)
        .await?;
    let stored = envelopes::store(
        &mut tx,
        req.vault_id,
        &req.envelope,
        auth.device_id,
        "replaced",
    )
    .await?;
    AuditEvent::new(AuditType::EnvelopeReplaced)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(req.vault_id)
        .ip(ip)
        .meta(serde_json::json!({ "recipient_type": enum_str(&recipient_type) }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    metrics::counter!("cc_recovery_attempts_total", "kind" => "envelope_replace").increment(1);
    state
        .events
        .publish_vault(
            &state.db,
            req.vault_id,
            ServerEvent::RecoveryChanged {
                vault_id: req.vault_id,
                recipient_type,
            },
        )
        .await;
    Ok(Json(stored))
}
