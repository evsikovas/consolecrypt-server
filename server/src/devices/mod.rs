// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Devices and device trust (`/v1/devices/*`, ADR-0004).

pub mod handlers;
pub mod protection;

use crate::auth::sessions;
use crate::config::DeviceProtectionConfig;
use crate::crypto;
use crate::error::{is_unique_violation, AppError, AppResult};
use crate::limiter::Quotas;
use crate::util::{enum_str, parse_enum, short_text, validate_device_name};
use cc_protocol::devices::{
    DeviceApprover, DeviceInfo, DeviceProof, DeviceRegistration, DeviceRequestStatus, DeviceStatus,
    DeviceTrustRequest,
};
use cc_protocol::{canonical, limits};
use cc_protocol::{DeviceId, DeviceRequestId, SessionId, UserId, VaultId};
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
/// A new device beyond the account's device quotas (`quota.v2`) → `403
/// forbidden` with `details.reason` `device_limit` / `device_daily_limit`.
pub async fn register_or_match(
    conn: &mut PgConnection,
    user_id: UserId,
    reg: &DeviceRegistration,
    proof: Option<&DeviceProof>,
    quota: &Quotas,
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
            if quota.v2 {
                check_device_quota(conn, user_id, quota).await?;
            }
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

/// TR-3: active devices per account and new devices per 24 hours, checked
/// under the account row lock (like the vault quota) so concurrent sign-ins
/// on any replica cannot overshoot.
async fn check_device_quota(
    conn: &mut PgConnection,
    user_id: UserId,
    quota: &Quotas,
) -> AppResult<()> {
    use cc_protocol::quotas::reason;
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(Uuid::from(user_id))
        .execute(&mut *conn)
        .await?;
    let (active, recent): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE revoked_at IS NULL),
                count(*) FILTER (WHERE created_at > now() - interval '1 day')
           FROM devices WHERE user_id = $1",
    )
    .bind(Uuid::from(user_id))
    .fetch_one(&mut *conn)
    .await?;
    if active >= quota.max_devices {
        metrics::counter!("cc_quota_rejected_total", "reason" => reason::DEVICE_LIMIT).increment(1);
        return Err(
            AppError::forbidden("device limit reached for this account").with_details(
                serde_json::json!({
                    "reason": reason::DEVICE_LIMIT,
                    "limit": quota.max_devices,
                }),
            ),
        );
    }
    let per_day = quota.new_devices_per_day;
    if per_day > 0 && recent >= per_day {
        // The window drops below the limit when the per_day-th newest device
        // of the last 24 hours leaves it.
        let until: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT created_at + interval '1 day' FROM devices
              WHERE user_id = $1 AND created_at > now() - interval '1 day'
              ORDER BY created_at DESC OFFSET $2 LIMIT 1",
        )
        .bind(Uuid::from(user_id))
        .bind(per_day - 1)
        .fetch_optional(&mut *conn)
        .await?;
        metrics::counter!("cc_quota_rejected_total", "reason" => reason::DEVICE_DAILY_LIMIT)
            .increment(1);
        return Err(
            AppError::forbidden("too many new devices for this account today").with_details(
                serde_json::json!({
                    "reason": reason::DEVICE_DAILY_LIMIT,
                    "limit": per_day,
                    "until": until.unwrap_or_else(|| Utc::now() + chrono::Duration::days(1)),
                }),
            ),
        );
    }
    Ok(())
}

/// Whether `proof` proves possession of `device_id`, an active device of
/// `user_id` (protocol 1.4 login proof). Read-only: the nonce must still be
/// unused and is consumed later by [`register_or_match`], so a proof seen
/// once can never vouch for a second sign-in attempt.
pub async fn is_known_device(
    db: &sqlx::PgPool,
    user_id: UserId,
    device_id: DeviceId,
    proof: &DeviceProof,
) -> AppResult<bool> {
    let key: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signing_public_key FROM devices
          WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(device_id))
    .bind(Uuid::from(user_id))
    .fetch_optional(db)
    .await?;
    let (Some(key), Some(nonce)) = (key, proof.nonce.to_array::<32>()) else {
        return Ok(false);
    };
    if Utc::now().timestamp().abs_diff(proof.issued_at) > limits::MAX_SIGNATURE_SKEW_SECONDS as u64
    {
        return Ok(false);
    }
    let message = canonical::device_login_message(device_id, proof.issued_at, &nonce);
    if !crypto::verify_ed25519(&key, &message, proof.signature.as_slice()) {
        return Ok(false);
    }
    let used: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM device_login_nonces WHERE device_id = $1 AND nonce = $2)",
    )
    .bind(Uuid::from(device_id))
    .bind(&nonce[..])
    .fetch_one(db)
    .await?;
    Ok(!used)
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
    pub quarantine_lifted_at: Option<DateTime<Utc>>,
    pub client_version: Option<String>,
}

const DEVICE_COLUMNS: &str = "id, name, platform, encryption_public_key, signing_public_key, \
                              created_at, last_seen_at, revoked_at, quarantine_lifted_at, \
                              client_version";

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

fn to_info(
    row: DeviceRow,
    trusted: Vec<VaultId>,
    current: DeviceId,
    prot: &DeviceProtectionConfig,
) -> AppResult<DeviceInfo> {
    let quarantine_until = protection::quarantine_end(
        prot,
        row.created_at,
        row.quarantine_lifted_at,
        row.revoked_at,
    );
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
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        revoked_at: row.revoked_at,
        is_current: row.id == Uuid::from(current),
        trusted: !trusted.is_empty(),
        quarantine_until,
        trusted_vaults: trusted,
        client_version: row.client_version,
    })
}

/// All devices of `user_id` (including revoked ones), oldest first.
pub(crate) async fn list_device_infos(
    db: &sqlx::PgPool,
    prot: &DeviceProtectionConfig,
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
            to_info(r, t, current, prot)
        })
        .collect()
}

/// One device of `user_id`, or `404`.
pub(crate) async fn device_info(
    db: &sqlx::PgPool,
    prot: &DeviceProtectionConfig,
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
    to_info(row, t, current, prot)
}

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: Uuid,
    device_id: Uuid,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    approved_by_device_id: Option<Uuid>,
    intent_device_id: Option<Uuid>,
    intent_at: Option<DateTime<Utc>>,
    vault_ids: Vec<Uuid>,
}

const REQUEST_SELECT: &str = "SELECT r.id, r.device_id, r.status, r.created_at, r.expires_at,
            r.approved_by_device_id, r.intent_device_id, r.intent_at,
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
    prot: &DeviceProtectionConfig,
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
        let device = device_info(db, prot, user_id, row.device_id.into(), current).await?;
        let approver = approver_of(db, user_id, &row).await?;
        out.push(request_to_dto(row, device, approver)?);
    }
    Ok(out)
}

/// The announced approver of a request (protocol 1.11), if any and still
/// an active device of the account.
async fn approver_of(
    db: &sqlx::PgPool,
    user_id: UserId,
    row: &RequestRow,
) -> AppResult<Option<DeviceApprover>> {
    let (Some(id), Some(at)) = (row.intent_device_id, row.intent_at) else {
        return Ok(None);
    };
    let found: Option<DeviceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {DEVICE_COLUMNS} FROM devices
          WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL"
    )))
    .bind(id)
    .bind(Uuid::from(user_id))
    .fetch_optional(db)
    .await?;
    let Some(d) = found else {
        return Ok(None);
    };
    Ok(Some(DeviceApprover {
        device_id: d.id.into(),
        name: d.name,
        platform: parse_enum(&d.platform)?,
        encryption_public_key: d.encryption_public_key.into(),
        signing_public_key: d.signing_public_key.into(),
        announced_at: at,
    }))
}

/// One trust request of `user_id`, or `404`.
pub(crate) async fn trust_request(
    db: &sqlx::PgPool,
    prot: &DeviceProtectionConfig,
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
    let device = device_info(db, prot, user_id, row.device_id.into(), current).await?;
    let approver = approver_of(db, user_id, &row).await?;
    request_to_dto(row, device, approver)
}

fn request_to_dto(
    row: RequestRow,
    device: DeviceInfo,
    approver: Option<DeviceApprover>,
) -> AppResult<DeviceTrustRequest> {
    Ok(DeviceTrustRequest {
        request_id: row.id.into(),
        device,
        vault_ids: row.vault_ids.into_iter().map(VaultId::from).collect(),
        status: effective_status(&row.status, row.expires_at)?,
        created_at: row.created_at,
        expires_at: row.expires_at,
        approved_by_device_id: row.approved_by_device_id.map(DeviceId::from),
        approver,
    })
}

/// What [`revoke_locked`] revoked.
pub(crate) struct Revocation {
    pub sessions: Vec<SessionId>,
    pub envelopes: u64,
}

/// Revoke a device whose row the caller has locked `FOR UPDATE` and found
/// active: its sessions, device envelopes and pending trust requests.
pub(crate) async fn revoke_locked(
    conn: &mut PgConnection,
    device_id: DeviceId,
    reason: Option<&str>,
    session_reason: &str,
) -> AppResult<Revocation> {
    sqlx::query("UPDATE devices SET revoked_at = now(), revoke_reason = $2 WHERE id = $1")
        .bind(Uuid::from(device_id))
        .bind(reason)
        .execute(&mut *conn)
        .await?;
    let sessions = sessions::revoke_device_sessions(conn, device_id, session_reason).await?;
    let envelopes = sqlx::query(
        "UPDATE vault_key_envelopes SET revoked_at = now(), revoke_reason = 'device_revoked'
          WHERE recipient_type = 'device' AND recipient_id = $1 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(device_id))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE device_requests SET status = 'rejected', decided_at = now()
          WHERE device_id = $1 AND status = 'pending'",
    )
    .bind(Uuid::from(device_id))
    .execute(&mut *conn)
    .await?;
    Ok(Revocation {
        sessions,
        envelopes,
    })
}

/// Status string for the DB.
pub(crate) fn status_str(s: DeviceRequestStatus) -> String {
    enum_str(&s)
}
