// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Devices and device trust (`/v1/devices/*`, ADR-0004).

pub mod handlers;

use crate::crypto;
use crate::error::{is_unique_violation, AppError, AppResult};
use crate::util::{enum_str, parse_enum, short_text, validate_device_name};
use cc_protocol::devices::{
    DeviceInfo, DeviceProof, DeviceRegistration, DeviceRequestStatus, DeviceStatus,
    DeviceTrustRequest,
};
use cc_protocol::{canonical, limits};
use cc_protocol::{DeviceId, DeviceRequestId, UserId, VaultId};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceOutcome {
    Created,
    Existing,
}

/// Structural checks of a device registration (keys, name, version).
pub fn validate_registration(reg: &DeviceRegistration) -> AppResult<()> {
    validate_device_name(&reg.name)?;
    if !crypto::is_valid_encryption_public_key(reg.encryption_public_key.as_slice()) {
        return Err(AppError::bad_request("invalid encryption_public_key"));
    }
    if !crypto::is_valid_signing_public_key(reg.signing_public_key.as_slice()) {
        return Err(AppError::bad_request("invalid signing_public_key"));
    }
    if reg.device_id.as_uuid().is_nil() {
        return Err(AppError::bad_request("invalid device_id"));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct ExistingDevice {
    user_id: Uuid,
    encryption_public_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    revoked: bool,
}

/// Register `reg` for `user_id`, or match it against the stored device.
///
/// Device ids are global (ADR-0201): an id owned by another account or with
/// different keys → `409 already_exists`; a revoked id → `403 device_revoked`.
pub async fn register_or_match(
    conn: &mut PgConnection,
    user_id: UserId,
    reg: &DeviceRegistration,
    proof: Option<&DeviceProof>,
) -> AppResult<DeviceOutcome> {
    let name = validate_device_name(&reg.name)?;
    let client_version = short_text(reg.client_version.as_deref(), 64);
    let existing: Option<ExistingDevice> = sqlx::query_as(
        "SELECT user_id, encryption_public_key, signing_public_key, revoked_at IS NOT NULL AS revoked
           FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(Uuid::from(reg.device_id))
    .fetch_optional(&mut *conn)
    .await?;

    match existing {
        None => {
            // Optional for a new device; if sent, it must be valid.
            if let Some(proof) = proof {
                verify_device_proof(
                    conn,
                    reg.device_id,
                    reg.signing_public_key.as_slice(),
                    proof,
                )
                .await?;
            }
            let res = sqlx::query(
                "INSERT INTO devices
                     (id, user_id, name, platform, encryption_public_key, signing_public_key,
                      client_version, last_seen_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
            )
            .bind(Uuid::from(reg.device_id))
            .bind(Uuid::from(user_id))
            .bind(&name)
            .bind(reg.platform.as_str())
            .bind(reg.encryption_public_key.as_slice())
            .bind(reg.signing_public_key.as_slice())
            .bind(client_version)
            .execute(&mut *conn)
            .await;
            match res {
                Err(err) if is_unique_violation(&err) => Err(device_id_taken()),
                Err(err) => Err(err.into()),
                Ok(_) => Ok(DeviceOutcome::Created),
            }
        }
        Some(d) if d.user_id != Uuid::from(user_id) => Err(device_id_taken()),
        Some(d) if d.revoked => Err(AppError::device_revoked()),
        Some(d)
            if d.encryption_public_key != reg.encryption_public_key.as_slice()
                || d.signing_public_key != reg.signing_public_key.as_slice() =>
        {
            Err(AppError::already_exists(
                "device_id",
                "device id is registered with different public keys",
            ))
        }
        Some(d) => {
            // ADR-0006: an existing device id is only usable by the holder
            // of its signing key (ids and public keys are not secret).
            let proof = proof.ok_or_else(|| proof_error("device_proof_required"))?;
            verify_device_proof(conn, reg.device_id, &d.signing_public_key, proof).await?;
            sqlx::query(
                "UPDATE devices SET name = $2, platform = $3,
                        client_version = COALESCE($4, client_version), last_seen_at = now()
                  WHERE id = $1",
            )
            .bind(Uuid::from(reg.device_id))
            .bind(&name)
            .bind(reg.platform.as_str())
            .bind(client_version)
            .execute(&mut *conn)
            .await?;
            Ok(DeviceOutcome::Existing)
        }
    }
}

fn proof_error(reason: &'static str) -> AppError {
    metrics::counter!("cc_auth_failures_total", "reason" => reason).increment(1);
    AppError::invalid_proof("device proof of possession missing or invalid")
        .with_details(serde_json::json!({ "reason": reason }))
}

/// Verify a login proof (ADR-0006) against `signing_key` and consume its
/// nonce. Order: shape, clock skew, signature, then the single-use nonce (so
/// garbage never reaches the nonce table).
pub async fn verify_device_proof(
    conn: &mut PgConnection,
    device_id: DeviceId,
    signing_key: &[u8],
    proof: &DeviceProof,
) -> AppResult<()> {
    let nonce: [u8; 32] = proof
        .nonce
        .to_array()
        .ok_or_else(|| AppError::bad_request("device_proof.nonce must be 32 bytes"))?;
    let now = Utc::now().timestamp();
    if now.abs_diff(proof.issued_at) > limits::MAX_SIGNATURE_SKEW_SECONDS as u64 {
        return Err(proof_error("stale"));
    }
    let message = canonical::device_login_message(device_id, proof.issued_at, &nonce);
    if !crypto::verify_ed25519(signing_key, &message, proof.signature.as_slice()) {
        return Err(proof_error("invalid_signature"));
    }
    // Keep the nonce until the proof could no longer pass the skew check.
    let expires_at = proof.issued_at.max(now) + limits::MAX_SIGNATURE_SKEW_SECONDS + 60;
    let inserted = sqlx::query(
        "INSERT INTO device_login_nonces (device_id, nonce, expires_at)
         VALUES ($1, $2, to_timestamp($3))
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from(device_id))
    .bind(&nonce[..])
    .bind(expires_at as f64)
    .execute(conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(proof_error("replayed"));
    }
    Ok(())
}

fn device_id_taken() -> AppError {
    AppError::already_exists(
        "device_id",
        "device id is already registered; generate a new device identity for this account",
    )
}

#[derive(sqlx::FromRow)]
pub(crate) struct DeviceRow {
    pub id: Uuid,
    pub name: String,
    pub platform: String,
    pub encryption_public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

const DEVICE_COLUMNS: &str = "id, name, platform, encryption_public_key, signing_public_key, \
                              created_at, last_seen_at, revoked_at";

/// Map device id → vaults it currently holds a live device envelope for
/// (excluding deleted vaults).
async fn trusted_vaults<'e>(
    db: impl PgExecutor<'e>,
    device_ids: &[Uuid],
) -> AppResult<HashMap<Uuid, Vec<VaultId>>> {
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT e.recipient_id, e.vault_id
           FROM vault_key_envelopes e
           JOIN vaults v ON v.id = e.vault_id
          WHERE e.recipient_type = 'device' AND e.revoked_at IS NULL
            AND v.state <> 'deleted' AND e.recipient_id = ANY($1)
          ORDER BY e.vault_id",
    )
    .bind(device_ids)
    .fetch_all(db)
    .await?;
    let mut map: HashMap<Uuid, Vec<VaultId>> = HashMap::new();
    for (device, vault) in rows {
        map.entry(device).or_default().push(vault.into());
    }
    Ok(map)
}

fn to_info(row: DeviceRow, trusted: Vec<VaultId>, current: DeviceId) -> AppResult<DeviceInfo> {
    Ok(DeviceInfo {
        device_id: row.id.into(),
        name: row.name,
        platform: parse_enum(&row.platform)?,
        encryption_public_key: row.encryption_public_key.into(),
        signing_public_key: row.signing_public_key.into(),
        status: if row.revoked_at.is_some() {
            DeviceStatus::Revoked
        } else {
            DeviceStatus::Active
        },
        trusted_vaults: trusted,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        revoked_at: row.revoked_at,
        is_current: row.id == Uuid::from(current),
    })
}

/// All devices of `user_id` (including revoked ones), oldest first.
pub(crate) async fn list_device_infos(
    db: &sqlx::PgPool,
    user_id: UserId,
    current: DeviceId,
) -> AppResult<Vec<DeviceInfo>> {
    let rows: Vec<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE user_id = $1 ORDER BY created_at, id"
    )))
    .bind(Uuid::from(user_id))
    .fetch_all(db)
    .await?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut trusted = trusted_vaults(db, &ids).await?;
    rows.into_iter()
        .map(|r| {
            let t = trusted.remove(&r.id).unwrap_or_default();
            to_info(r, t, current)
        })
        .collect()
}

/// One device of `user_id`, or `404`.
pub(crate) async fn device_info(
    db: &sqlx::PgPool,
    user_id: UserId,
    device_id: DeviceId,
    current: DeviceId,
) -> AppResult<DeviceInfo> {
    let row: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE id = $1 AND user_id = $2"
    )))
    .bind(Uuid::from(device_id))
    .bind(Uuid::from(user_id))
    .fetch_optional(db)
    .await?;
    let row = row.ok_or_else(AppError::not_found)?;
    let mut trusted = trusted_vaults(db, &[row.id]).await?;
    let t = trusted.remove(&row.id).unwrap_or_default();
    to_info(row, t, current)
}

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: Uuid,
    device_id: Uuid,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    approved_by_device_id: Option<Uuid>,
    vault_ids: Vec<Uuid>,
}

const REQUEST_SELECT: &str = "SELECT r.id, r.device_id, r.status, r.created_at, r.expires_at,
            r.approved_by_device_id,
            COALESCE(array_agg(rv.vault_id ORDER BY rv.vault_id)
                     FILTER (WHERE rv.vault_id IS NOT NULL), '{}') AS vault_ids
       FROM device_requests r
       LEFT JOIN device_request_vaults rv ON rv.request_id = r.id";

fn effective_status(status: &str, expires_at: DateTime<Utc>) -> AppResult<DeviceRequestStatus> {
    let s: DeviceRequestStatus = parse_enum(status)?;
    Ok(
        if s == DeviceRequestStatus::Pending && expires_at <= Utc::now() {
            DeviceRequestStatus::Expired
        } else {
            s
        },
    )
}

/// Live (pending, unexpired) trust requests of `user_id`.
pub(crate) async fn pending_requests(
    db: &sqlx::PgPool,
    user_id: UserId,
    current: DeviceId,
) -> AppResult<Vec<DeviceTrustRequest>> {
    let rows: Vec<RequestRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{REQUEST_SELECT}
          WHERE r.user_id = $1 AND r.status = 'pending' AND r.expires_at > now()
          GROUP BY r.id ORDER BY r.created_at"
    )))
    .bind(Uuid::from(user_id))
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let device = device_info(db, user_id, row.device_id.into(), current).await?;
        out.push(request_to_dto(row, device)?);
    }
    Ok(out)
}

/// One trust request of `user_id`, or `404`.
pub(crate) async fn trust_request(
    db: &sqlx::PgPool,
    user_id: UserId,
    request_id: DeviceRequestId,
    current: DeviceId,
) -> AppResult<DeviceTrustRequest> {
    let row: Option<RequestRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{REQUEST_SELECT} WHERE r.id = $1 AND r.user_id = $2 GROUP BY r.id"
    )))
    .bind(Uuid::from(request_id))
    .bind(Uuid::from(user_id))
    .fetch_optional(db)
    .await?;
    let row = row.ok_or_else(AppError::not_found)?;
    let device = device_info(db, user_id, row.device_id.into(), current).await?;
    request_to_dto(row, device)
}

fn request_to_dto(row: RequestRow, device: DeviceInfo) -> AppResult<DeviceTrustRequest> {
    Ok(DeviceTrustRequest {
        request_id: row.id.into(),
        device,
        vault_ids: row.vault_ids.into_iter().map(VaultId::from).collect(),
        status: effective_status(&row.status, row.expires_at)?,
        created_at: row.created_at,
        expires_at: row.expires_at,
        approved_by_device_id: row.approved_by_device_id.map(DeviceId::from),
    })
}

/// Status string for the DB.
pub(crate) fn status_str(s: DeviceRequestStatus) -> String {
    enum_str(&s)
}
