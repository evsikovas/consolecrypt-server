//! Fixed bounded owner opt-in. The selected vault exists already; scope is
//! explicitly PERSONAL ACCOUNT, with a per-selected-vault pull checkpoint.
use super::*;
use crate::vaults::access::{require_access_key, VaultAccess};
use crate::{
    audit::AuditType,
    auth::AuthContext,
    extract::{ApiJson, ApiPath, ClientIp},
    AppState,
};
use axum::{extract::State, Json};
use cc_protocol::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OptInRequest {
    version: u32,
    expected_revision: u64,
    expected_roster_digest: String,
    vault_access_key: Bytes,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityView {
    version: u32,
    scope: &'static str,
    account_id: UserId,
    revision: u64,
    state: &'static str,
    minimum_client_version: Option<String>,
    offer_minimum_client_version: Option<String>,
    roster_digest: String,
    checkpoint: Checkpoint,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Checkpoint {
    vault_id: VaultId,
    vault_epoch: Uuid,
    vault_sequence: i64,
}
#[derive(sqlx::FromRow)]
struct Policy {
    version: i32,
    revision: i64,
    minimum_client_version: Option<String>,
    quarantined: bool,
}
async fn policy(conn: &mut PgConnection, user: UserId) -> AppResult<Option<Policy>> {
    Ok(sqlx::query_as("SELECT version,revision,minimum_client_version,quarantined FROM account_monitoring_compatibility WHERE user_id=$1")
      .bind(Uuid::from(user)).fetch_optional(conn).await?)
}
fn conflict(reason: &'static str) -> AppError {
    AppError::new(ErrorCode::Conflict, "compatibility context changed")
        .with_details(serde_json::json!({"reason":reason}))
}
async fn roster(
    conn: &mut PgConnection,
    user: UserId,
) -> AppResult<(String, Vec<(Uuid, Option<String>)>)> {
    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id,CASE WHEN octet_length(client_version)<=64 THEN client_version ELSE NULL END
         FROM devices WHERE user_id=$1 AND revoked_at IS NULL ORDER BY id LIMIT 257",
    )
    .bind(Uuid::from(user))
    .fetch_all(conn)
    .await?;
    if rows.is_empty() || rows.len() > 256 {
        return Err(AppError::forbidden("compatibility roster exceeds budget"));
    }
    let bytes = serde_json::to_vec(&rows)
        .map_err(|_| AppError::internal("compatibility roster serialization failed"))?;
    let mut domain = b"cc.monitoring-compatibility-roster.v1\0".to_vec();
    domain.extend_from_slice(&bytes);
    let digest = crate::crypto::sha256(&domain)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((digest, rows))
}
async fn checkpoint(conn: &mut PgConnection, vault: VaultId) -> AppResult<Checkpoint> {
    let (vault_epoch, vault_sequence): (Uuid, i64) = sqlx::query_as(
        "/* cc.compat.checkpoint */ SELECT v.epoch,s.last_sequence FROM vault_sequences s
       JOIN vaults v ON v.id=s.vault_id WHERE v.id=$1 AND v.state='active' FOR UPDATE OF s",
    )
    .bind(Uuid::from(vault))
    .fetch_optional(conn)
    .await?
    .ok_or_else(AppError::not_found)?;
    Ok(Checkpoint {
        vault_id: vault,
        vault_epoch,
        vault_sequence,
    })
}
async fn owner(
    conn: &mut PgConnection,
    auth: &AuthContext,
    vault: VaultId,
) -> AppResult<VaultAccess> {
    let access = VaultAccess::load(conn, auth, vault).await?;
    if access.is_team
        || access.owner_user_id != auth.user_id
        || access.role != cc_protocol::vaults::VaultRole::Owner
    {
        return Err(AppError::not_found());
    }
    access.require_trusted()?;
    Ok(access)
}
async fn actor(conn: &mut PgConnection, auth: &AuthContext) -> AppResult<()> {
    // Explicit lock order: account -> caller device -> session -> sequence.
    // Revoke takes device then sessions; never invert that pair here.
    let active: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NULL FROM devices WHERE id=$1 AND user_id=$2 FOR SHARE",
    )
    .bind(Uuid::from(auth.device_id))
    .bind(Uuid::from(auth.user_id))
    .fetch_optional(&mut *conn)
    .await?;
    if active != Some(true) {
        return Err(AppError::device_revoked());
    }
    let current:Option<bool>=sqlx::query_scalar("SELECT revoked_at IS NULL AND access_expires_at>now() AND expires_at>now() AND access_token_hash=$4
       FROM sessions WHERE id=$1 AND user_id=$2 AND device_id=$3 FOR SHARE")
      .bind(Uuid::from(auth.session_id)).bind(Uuid::from(auth.user_id)).bind(Uuid::from(auth.device_id))
      .bind(&auth.access_token_hash[..]).fetch_optional(&mut *conn).await?;
    let enabled: bool = sqlx::query_scalar("SELECT status='active' FROM users WHERE id=$1")
        .bind(Uuid::from(auth.user_id))
        .fetch_one(conn)
        .await?;
    if current != Some(true) || !enabled {
        return Err(AppError::unauthorized());
    }
    Ok(())
}
fn view(
    user: UserId,
    row: Option<Policy>,
    offer: Option<String>,
    roster_digest: String,
    checkpoint: Checkpoint,
) -> AppResult<CompatibilityView> {
    if row
        .as_ref()
        .is_some_and(|r| r.version != 1 || r.revision < 1)
    {
        return Err(quarantined());
    }
    let state = match row.as_ref() {
        None => "off",
        Some(r) if r.quarantined => "quarantined",
        Some(_) => "enabled",
    };
    Ok(CompatibilityView {
        version: 1,
        scope: "personalAccount",
        account_id: user,
        revision: row.as_ref().map_or(0, |r| r.revision as u64),
        state,
        minimum_client_version: row.and_then(|r| r.minimum_client_version),
        offer_minimum_client_version: offer,
        roster_digest,
        checkpoint,
    })
}
/// Read is metadata only; it does not confer a lease or authorize new schemas.
pub async fn read(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiPath(vault): ApiPath<VaultId>,
) -> AppResult<Json<CompatibilityView>> {
    if auth.client_version.is_none() {
        return Err(required());
    }
    let mut tx = state.db.begin().await?;
    lock_account(&mut tx, auth.user_id).await?;
    actor(&mut tx, &auth).await?;
    check_admission(&mut *tx, auth.user_id, auth.client_version).await?;
    owner(&mut tx, &auth, vault).await?;
    let checkpoint = checkpoint(&mut tx, vault).await?;
    let (digest, _) = roster(&mut tx, auth.user_id).await?;
    let row = policy(&mut tx, auth.user_id).await?;
    let output = view(
        auth.user_id,
        row,
        state.config.monitoring_preservation_minimum.clone(),
        digest,
        checkpoint,
    )?;
    tx.commit().await?;
    Ok(Json(output))
}
pub async fn opt_in(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiPath(vault): ApiPath<VaultId>,
    ApiJson(req): ApiJson<OptInRequest>,
) -> AppResult<Json<CompatibilityView>> {
    if !state.config.require_request_proof {
        return Err(AppError::not_found());
    }
    let offered = state
        .config
        .monitoring_preservation_minimum
        .as_deref()
        .and_then(ClientVersion::release)
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "compatibility opt-in is unavailable"))?;
    if req.version != 1
        || req.expected_revision > i64::MAX as u64
        || req.vault_access_key.len() != 32
        || req.expected_roster_digest.len() != 64
        || !req
            .expected_roster_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AppError::bad_request("invalid compatibility request"));
    }
    // Validate K(V) before holding the transaction lock (proof failure auditing
    // uses the pool). Repeat owner/T(V)/K(V) under locks before the write.
    let access = VaultAccess::load(&state.db, &auth, vault).await?;
    if access.owner_user_id != auth.user_id || access.is_team {
        return Err(AppError::not_found());
    }
    access.require_trusted()?;
    require_access_key(
        &state,
        &auth,
        ip,
        &access,
        &req.vault_access_key,
        AuditType::VaultProofFailed,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    lock_account(&mut tx, auth.user_id).await?;
    actor(&mut tx, &auth).await?;
    let access = owner(&mut tx, &auth, vault).await?;
    if !access.key_matches(&req.vault_access_key) {
        return Err(AppError::invalid_proof("vault context changed"));
    }
    let shared:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vaults v JOIN vault_members m ON m.vault_id=v.id
       WHERE v.owner_user_id=$1 AND v.kind='personal' AND v.state<>'deleted' AND m.revoked_at IS NULL AND m.user_id<>$1)")
      .bind(Uuid::from(auth.user_id)).fetch_one(&mut *tx).await?;
    if shared {
        return Err(AppError::forbidden(
            "shared personal compatibility scope is unsupported",
        ));
    }
    let checkpoint = checkpoint(&mut tx, vault).await?;
    let before = policy(&mut tx, auth.user_id).await?;
    if before.as_ref().is_some_and(|r| r.version != 1) {
        return Err(quarantined());
    }
    let revision = before.as_ref().map_or(0, |r| r.revision);
    if revision < 0 || revision as u64 != req.expected_revision || revision == i64::MAX {
        return Err(conflict("compatibility_revision"));
    }
    let previous = match before
        .as_ref()
        .and_then(|p| p.minimum_client_version.as_deref())
    {
        None => None,
        Some(text) => Some(ClientVersion::release(text).ok_or_else(quarantined)?),
    };
    let minimum = previous.map_or(offered, |old| old.max(offered));
    if auth.client_version.is_none_or(|v| v < minimum) {
        return Err(required());
    }
    let (digest, devices) = roster(&mut tx, auth.user_id).await?;
    if digest != req.expected_roster_digest {
        return Err(conflict("compatibility_roster"));
    }
    if !devices
        .iter()
        .any(|(id, _)| *id == Uuid::from(auth.device_id))
        || devices.iter().any(|(_, v)| {
            v.as_deref()
                .and_then(ClientVersion::parse)
                .is_none_or(|v| v < minimum)
        })
    {
        return Err(required());
    }
    let minimum = minimum.to_string();
    sqlx::query("INSERT INTO account_monitoring_compatibility(user_id,revision,minimum_client_version,quarantined,enabled_by_device_id)
      VALUES($1,$2,$3,false,$4) ON CONFLICT(user_id) DO UPDATE SET revision=EXCLUDED.revision,
      minimum_client_version=EXCLUDED.minimum_client_version,quarantined=false,enabled_by_device_id=EXCLUDED.enabled_by_device_id,updated_at=now()")
      .bind(Uuid::from(auth.user_id)).bind(revision+1).bind(&minimum).bind(Uuid::from(auth.device_id)).execute(&mut *tx).await?;
    let output = view(
        auth.user_id,
        Some(Policy {
            version: 1,
            revision: revision + 1,
            minimum_client_version: Some(minimum),
            quarantined: false,
        }),
        state.config.monitoring_preservation_minimum.clone(),
        digest,
        checkpoint,
    )?;
    crate::audit::AuditEvent::new(AuditType::MonitoringCompatibilityEnabled)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(vault)
        .meta(
            serde_json::json!({"scope":"personalAccount","revision":revision+1,
        "minimum_client_version":output.minimum_client_version}),
        )
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(output))
}
