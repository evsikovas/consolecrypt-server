// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Vault recovery (`/v1/recovery/vault/*`, ADR-0004). The server validates
//! authorization and stores opaque envelopes; it never decrypts anything.
//! Account recovery (`/v1/recovery/account/*`) lives in `auth::handlers` and
//! never grants vault access.

use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::error::AppResult;
use crate::extract::{ApiJson, ApiQuery, ClientIp};
use crate::state::AppState;
use crate::util::enum_str;
use crate::vaults::access::require_trusted_with_key;
use crate::vaults::envelopes;
use crate::vaults::VaultAccess;
use axum::extract::State;
use axum::Json;
use cc_protocol::envelopes::{KeyEnvelope, RecipientType};
use cc_protocol::events::ServerEvent;
use cc_protocol::recovery::{RecoveryMaterialQuery, ReplaceEnvelopeRequest, VaultRecoveryMaterial};
use std::net::IpAddr;
use uuid::Uuid;

/// `GET /v1/recovery/vault/envelope?vault_id` — any active device of a member.
pub async fn vault_material(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiQuery(q): ApiQuery<RecoveryMaterialQuery>,
) -> AppResult<Json<VaultRecoveryMaterial>> {
    VaultAccess::load(&state.db, &auth, q.vault_id).await?;
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
    metrics::counter!("cc_recovery_attempts_total", "kind" => "vault_material").increment(1);
    Ok(Json(VaultRecoveryMaterial {
        vault_id: q.vault_id,
        password_envelope,
        recovery_envelope,
        device_envelope,
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
    envelopes::validate(&req.envelope, recipient_type)?;
    require_trusted_with_key(state, auth, ip, req.vault_id, &req.vault_access_key).await?;

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
