// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `/v1/vaults/*` handlers.

use super::access::{require_trusted_with_key, VaultAccess};
use super::envelopes::{self, Visibility};
use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::extract::{ApiJson, ApiJsonOrDefault, ApiPath, ClientIp};
use crate::state::AppState;
use crate::util::enum_str;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cc_protocol::envelopes::{KeyEnvelope, RecipientType};
use cc_protocol::limits;
use cc_protocol::vaults::{
    CreateEnvelopeRequest, CreateVaultRequest, DeleteEnvelopeRequest, DeleteVaultRequest,
    ListEnvelopesResponse, ListVaultsResponse, VaultInfo, VaultRole, VaultState,
};
use cc_protocol::{EnvelopeId, ErrorCode, VaultId};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// `POST /v1/vaults` → `201 VaultInfo`. The calling device becomes trusted.
pub async fn create_vault(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<CreateVaultRequest>,
) -> AppResult<(StatusCode, Json<VaultInfo>)> {
    if state.config.require_email_verification && !auth.email_verified {
        return Err(AppError::new(
            ErrorCode::EmailNotVerified,
            "verify your email address before creating a vault",
        ));
    }
    if req.vault_id.as_uuid().is_nil() {
        return Err(AppError::bad_request("invalid vault_id"));
    }
    if req.vault_access_key.len() != limits::VAULT_ACCESS_KEY_LEN {
        return Err(AppError::bad_request("vault_access_key must be 32 bytes"));
    }
    envelopes::validate(&req.password_envelope, RecipientType::Password)?;
    envelopes::validate(&req.recovery_envelope, RecipientType::Recovery)?;
    envelopes::validate(&req.device_envelope, RecipientType::Device)?;
    if req.device_envelope.recipient_id != Some(auth.device_id.into()) {
        return Err(AppError::bad_request(
            "device_envelope must be addressed to the calling device",
        ));
    }

    let verifier = crypto::vault_access_key_verifier(req.vault_access_key.as_slice());
    let mut tx = state.db.begin().await?;
    // Serialise this account's vault creations so the quota check is exact.
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(Uuid::from(auth.user_id))
        .execute(&mut *tx)
        .await?;
    let owned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM vaults WHERE owner_user_id = $1 AND state <> 'deleted'",
    )
    .bind(Uuid::from(auth.user_id))
    .fetch_one(&mut *tx)
    .await?;
    if owned >= state.config.max_vaults_per_account {
        return Err(
            AppError::forbidden("vault limit reached for this account").with_details(
                serde_json::json!({
                    "reason": "vault_limit",
                    "limit": state.config.max_vaults_per_account,
                }),
            ),
        );
    }
    let created: Option<(DateTime<Utc>, Uuid)> = sqlx::query_as(
        "INSERT INTO vaults (id, owner_user_id, access_key_verifier, created_by_device_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING
         RETURNING created_at, epoch",
    )
    .bind(Uuid::from(req.vault_id))
    .bind(Uuid::from(auth.user_id))
    .bind(&verifier[..])
    .bind(Uuid::from(auth.device_id))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((created_at, epoch)) = created else {
        return Err(AppError::already_exists(
            "vault_id",
            "a vault with this id already exists",
        ));
    };
    sqlx::query("INSERT INTO vault_members (vault_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(Uuid::from(req.vault_id))
        .bind(Uuid::from(auth.user_id))
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO vault_sequences (vault_id, last_sequence) VALUES ($1, 0)")
        .bind(Uuid::from(req.vault_id))
        .execute(&mut *tx)
        .await?;
    for env in [
        &req.password_envelope,
        &req.recovery_envelope,
        &req.device_envelope,
    ] {
        envelopes::store(&mut tx, req.vault_id, env, auth.device_id, "replaced").await?;
    }
    AuditEvent::new(AuditType::VaultCreated)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(req.vault_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(VaultInfo {
            vault_id: req.vault_id,
            owner_user_id: auth.user_id,
            role: VaultRole::Owner,
            state: VaultState::Active,
            created_at,
            updated_at: created_at,
            latest_sequence: 0,
            caller_trusted: true,
            deletion_scheduled_at: None,
            epoch: Some(epoch),
        }),
    ))
}

#[derive(sqlx::FromRow)]
struct VaultListRow {
    id: Uuid,
    owner_user_id: Uuid,
    role: String,
    state: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deletion_scheduled_at: Option<DateTime<Utc>>,
    last_sequence: i64,
    trusted: bool,
    epoch: Uuid,
}

/// `GET /v1/vaults` → vaults the account is a member of (not deleted).
pub async fn list_vaults(
    State(state): State<AppState>,
    auth: AuthContext,
) -> AppResult<Json<ListVaultsResponse>> {
    let rows: Vec<VaultListRow> = sqlx::query_as(
        "SELECT v.id, v.owner_user_id, m.role, v.state, v.created_at, v.updated_at,
                v.deletion_scheduled_at, v.epoch, s.last_sequence,
                EXISTS (SELECT 1 FROM vault_key_envelopes e
                         WHERE e.vault_id = v.id AND e.recipient_type = 'device'
                           AND e.recipient_id = $2 AND e.revoked_at IS NULL) AS trusted
           FROM vault_members m
           JOIN vaults v ON v.id = m.vault_id
           JOIN vault_sequences s ON s.vault_id = v.id
          WHERE m.user_id = $1 AND m.revoked_at IS NULL AND v.state <> 'deleted'
          ORDER BY v.created_at, v.id",
    )
    .bind(Uuid::from(auth.user_id))
    .bind(Uuid::from(auth.device_id))
    .fetch_all(&state.db)
    .await?;
    let vaults = rows
        .into_iter()
        .map(|r| {
            Ok(VaultInfo {
                vault_id: r.id.into(),
                owner_user_id: r.owner_user_id.into(),
                role: crate::util::parse_enum(&r.role)?,
                state: crate::util::parse_enum(&r.state)?,
                created_at: r.created_at,
                updated_at: r.updated_at,
                latest_sequence: r.last_sequence,
                caller_trusted: r.trusted,
                deletion_scheduled_at: r.deletion_scheduled_at,
                epoch: Some(r.epoch),
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(ListVaultsResponse { vaults }))
}

/// `GET /v1/vaults/{vault_id}` → `VaultInfo` (member).
pub async fn get_vault(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault_id): ApiPath<VaultId>,
) -> AppResult<Json<VaultInfo>> {
    let access = VaultAccess::load(&state.db, &auth, vault_id).await?;
    Ok(Json(access.info()))
}

/// `DELETE /v1/vaults/{vault_id}` → `204`. T(V) + K(V): soft delete; the
/// ciphertext is purged by the retention job.
pub async fn delete_vault(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(vault_id): ApiPath<VaultId>,
    ApiJsonOrDefault(req): ApiJsonOrDefault<DeleteVaultRequest>,
) -> AppResult<StatusCode> {
    // TODO(server): untrusted `pending_deletion` with a grace period — deferred
    // because cancelling needs a protocol addition (ADR-0202 §Vault deletion);
    // next: add the cancel route with Client Dev, then schedule here.
    let vak = req
        .vault_access_key
        .ok_or_else(|| AppError::bad_request("vault_access_key is required"))?;
    let access = require_trusted_with_key(&state, &auth, ip, vault_id, &vak).await?;
    if access.role != VaultRole::Owner {
        return Err(AppError::forbidden("only the owner can delete a vault"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE vaults SET state = 'deleted', deleted_at = now(), updated_at = now()
          WHERE id = $1 AND state <> 'deleted'",
    )
    .bind(Uuid::from(vault_id))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE device_requests SET status = 'rejected', decided_at = now()
          WHERE status = 'pending'
            AND id IN (SELECT request_id FROM device_request_vaults WHERE vault_id = $1)
            AND NOT EXISTS (SELECT 1 FROM device_request_vaults rv
                             JOIN vaults v ON v.id = rv.vault_id
                            WHERE rv.request_id = device_requests.id AND v.state <> 'deleted')",
    )
    .bind(Uuid::from(vault_id))
    .execute(&mut *tx)
    .await?;
    AuditEvent::new(AuditType::VaultDeleted)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(vault_id)
        .ip(ip)
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/vaults/{vault_id}/envelopes`: trusted → all live envelopes;
/// untrusted member → password + recovery + own device envelope.
pub async fn list_envelopes(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault_id): ApiPath<VaultId>,
) -> AppResult<Json<ListEnvelopesResponse>> {
    let access = VaultAccess::load(&state.db, &auth, vault_id).await?;
    let visibility = if access.trusted {
        Visibility::All
    } else {
        Visibility::UnlockMaterial {
            device_id: auth.device_id,
        }
    };
    let envelopes = envelopes::list_live(&state.db, vault_id, visibility).await?;
    Ok(Json(ListEnvelopesResponse { envelopes }))
}

/// `POST /v1/vaults/{vault_id}/envelopes` → `201 KeyEnvelope`. T(V) + K(V).
/// For re-keying the caller's own device envelope and (Team Vault) `user`
/// envelopes of current members. Other devices are added via approve;
/// password/recovery via the replace endpoints.
pub async fn create_envelope(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(vault_id): ApiPath<VaultId>,
    ApiJson(req): ApiJson<CreateEnvelopeRequest>,
) -> AppResult<(StatusCode, Json<KeyEnvelope>)> {
    let env = &req.envelope;
    match env.recipient_type {
        RecipientType::Device => {
            envelopes::validate(env, RecipientType::Device)?;
            if env.recipient_id != Some(auth.device_id.into()) {
                return Err(AppError::bad_request(
                    "device envelopes for other devices are added via /v1/devices/{id}/approve",
                ));
            }
        }
        RecipientType::User => envelopes::validate(env, RecipientType::User)?,
        RecipientType::Password | RecipientType::Recovery => return Err(AppError::bad_request(
            "password/recovery envelopes are replaced via /v1/recovery/vault/*-envelope/replace",
        )),
        RecipientType::OrganizationFuture => {
            return Err(AppError::bad_request("recipient type not supported"))
        }
    }
    require_trusted_with_key(&state, &auth, ip, vault_id, &req.vault_access_key).await?;

    let mut tx = state.db.begin().await?;
    if env.recipient_type == RecipientType::User {
        let member: Option<(Uuid,)> = sqlx::query_as(
            "SELECT user_id FROM vault_members
              WHERE vault_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(Uuid::from(vault_id))
        .bind(env.recipient_id)
        .fetch_optional(&mut *tx)
        .await?;
        if member.is_none() {
            return Err(AppError::bad_request(
                "user envelopes can only be addressed to vault members",
            ));
        }
    }
    let stored = envelopes::store(&mut tx, vault_id, env, auth.device_id, "replaced").await?;
    AuditEvent::new(AuditType::EnvelopeCreated)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(stored.envelope_id)
        .ip(ip)
        .meta(serde_json::json!({
            "vault_id": vault_id,
            "recipient_type": enum_str(&env.recipient_type),
        }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(stored)))
}

/// `DELETE /v1/vaults/{vault_id}/envelopes/{envelope_id}` → `204`. T(V) + K(V);
/// only device/user envelopes (password/recovery can only be replaced).
pub async fn delete_envelope(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath((vault_id, envelope_id)): ApiPath<(VaultId, EnvelopeId)>,
    ApiJson(req): ApiJson<DeleteEnvelopeRequest>,
) -> AppResult<StatusCode> {
    require_trusted_with_key(&state, &auth, ip, vault_id, &req.vault_access_key).await?;
    let mut tx = state.db.begin().await?;
    let found: Option<(String,)> = sqlx::query_as(
        "SELECT recipient_type FROM vault_key_envelopes
          WHERE id = $1 AND vault_id = $2 AND revoked_at IS NULL
          FOR UPDATE",
    )
    .bind(Uuid::from(envelope_id))
    .bind(Uuid::from(vault_id))
    .fetch_optional(&mut *tx)
    .await?;
    let (recipient_type,) = found.ok_or_else(AppError::not_found)?;
    if matches!(recipient_type.as_str(), "password" | "recovery") {
        return Err(AppError::bad_request(
            "the password/recovery envelope cannot be deleted; replace it instead",
        ));
    }
    sqlx::query(
        "UPDATE vault_key_envelopes SET revoked_at = now(), revoke_reason = 'deleted' WHERE id = $1",
    )
    .bind(Uuid::from(envelope_id))
    .execute(&mut *tx)
    .await?;
    AuditEvent::new(AuditType::EnvelopeDeleted)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(envelope_id)
        .ip(ip)
        .meta(serde_json::json!({ "vault_id": vault_id, "recipient_type": recipient_type }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
