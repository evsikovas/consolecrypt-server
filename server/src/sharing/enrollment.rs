// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-online enrollment. Verifies public proofs only; never decrypts challenges.
use super::{
    auth::{lock_identities, recheck_session, DeviceKeys},
    enrollment_store as records, require_enabled, service, store,
};
use crate::{
    audit::{AuditEvent, AuditType},
    auth::AuthContext,
    crypto,
    error::{AppError, AppResult},
    AppState,
};
use cc_protocol::{
    sharing::{AccessManifest, SharedItemState, SharingMember, SharingOperation, SharingRole},
    sharing_enrollment::*,
    Bytes, ShareId,
};
use chrono::Utc;
use sqlx::{types::Json, PgConnection};
use std::collections::BTreeMap;
use uuid::Uuid;

fn invalid(_: EnrollmentValidationError) -> AppError {
    AppError::bad_request("invalid enrollment payload")
}
fn bad() -> AppError {
    AppError::bad_request("enrollment binding mismatch")
}
fn hash(input: Result<Vec<u8>, EnrollmentValidationError>) -> AppResult<Vec<u8>> {
    Ok(crypto::sha256(&input.map_err(invalid)?).to_vec())
}
fn verify(
    key: &[u8],
    message: Result<Vec<u8>, EnrollmentValidationError>,
    signature: &Bytes,
) -> AppResult<()> {
    if !crypto::verify_ed25519(key, &message.map_err(invalid)?, signature.as_slice()) {
        return Err(AppError::invalid_proof("invalid enrollment signature"));
    }
    Ok(())
}
fn current(not_before: i64, expires_at: i64) -> AppResult<()> {
    let now = Utc::now().timestamp();
    if now < not_before || now >= expires_at {
        return Err(records::conflict());
    }
    Ok(())
}
fn enabled(state: &AppState, access: &AccessManifest) -> AppResult<()> {
    require_enabled(state)?;
    if !state.config.sharing_owner_online_enrollment_enabled
        || !service::kind_enabled(&state.config, access.kind)
    {
        return Err(AppError::not_found());
    }
    Ok(())
}
fn scope_matches(scope: &EnrollmentScope, access: &AccessManifest) -> bool {
    scope.server_instance_id == access.server_instance_id
        && scope.share_id == access.share_id
        && scope.item_id == access.item_id
        && scope.kind == access.kind
}
fn is_owner(access: &AccessManifest, auth: &AuthContext) -> bool {
    access.owner_user_id == auth.user_id && access.owner_device_id == auth.device_id
}
fn owner_key(access: &AccessManifest) -> AppResult<&SharingMember> {
    access
        .members
        .iter()
        .find(|m| m.device_id == access.owner_device_id && m.user_id == access.owner_user_id)
        .ok_or_else(bad)
}
fn require_owner(
    access: &AccessManifest,
    auth: &AuthContext,
    keys: &BTreeMap<Uuid, DeviceKeys>,
) -> AppResult<()> {
    if !is_owner(access, auth) {
        return Err(AppError::not_found());
    }
    service::check_member_keys(owner_key(access)?, &keys[&Uuid::from(auth.device_id)])
}
fn member_matches(member: &SharingMember, device: &EnrollmentDeviceBinding) -> bool {
    member.user_id == device.user_id
        && member.device_id == device.device_id
        && member.encryption_public_key == device.encryption_public_key
        && member.signing_public_key == device.signing_public_key
}
fn device_matches(
    device: &EnrollmentDeviceBinding,
    keys: &BTreeMap<Uuid, DeviceKeys>,
) -> AppResult<()> {
    let Some(key) = keys.get(&Uuid::from(device.device_id)) else {
        return Err(bad());
    };
    if key.user_id != Uuid::from(device.user_id)
        || key.encryption.as_slice() != device.encryption_public_key.as_slice()
        || key.signing.as_slice() != device.signing_public_key.as_slice()
        || !crypto::is_valid_encryption_public_key(device.encryption_public_key.as_slice())
    {
        return Err(AppError::invalid_proof("enrollment device keys changed"));
    }
    Ok(())
}
fn role_allows(ceiling: SharingRole, role: SharingRole) -> bool {
    ceiling == SharingRole::Editor || role == SharingRole::Reader
}
fn grant_signature(
    grant: &SignedSharingOwnDevicesGrantState,
    access: &AccessManifest,
) -> AppResult<()> {
    if !scope_matches(&grant.grant.scope, access)
        || grant.grant.owner_user_id != access.owner_user_id
        || grant.grant.owner_device_id != access.owner_device_id
    {
        return Err(bad());
    }
    verify(
        owner_key(access)?.signing_public_key.as_slice(),
        enrollment_grant_message(&grant.grant),
        &grant.signature,
    )
}
fn active_grant(
    grant: &SignedSharingOwnDevicesGrantState,
    access: &AccessManifest,
) -> AppResult<()> {
    grant_signature(grant, access)?;
    let g = &grant.grant;
    if g.status != EnrollmentGrantStatus::Active
        || g.access_epoch != access.access_epoch
        || g.access_manifest_hash.as_slice() != service::manifest_hash(access)?
    {
        return Err(records::conflict());
    }
    current(g.not_before, g.expires_at)?;
    let anchor = access
        .members
        .iter()
        .find(|m| member_matches(m, &g.anchor))
        .ok_or_else(bad)?;
    if !role_allows(anchor.role, g.role_ceiling) {
        return Err(bad());
    }
    Ok(())
}
fn submission(
    grant: &SignedSharingOwnDevicesGrantState,
    state: &OwnDeviceRequestState,
    access: &AccessManifest,
) -> AppResult<()> {
    active_grant(grant, access)?;
    validate_request_for_grant(&state.request.request, &grant.grant).map_err(invalid)?;
    let r = &state.request.request;
    if state.grant_id != grant.grant.grant_id
        || r.grant_state_hash.as_slice() != hash(enrollment_grant_hash_input(grant))?
        || access
            .members
            .iter()
            .any(|m| m.device_id == r.target.device_id)
    {
        return Err(records::conflict());
    }
    current(r.not_before, r.expires_at)?;
    verify(
        r.target.signing_public_key.as_slice(),
        enrollment_request_message(r),
        &state.request.signature,
    )?;
    let e = &state.endorsement.endorsement;
    if e.anchor_device_id != grant.grant.anchor.device_id
        || e.request_hash.as_slice() != hash(enrollment_request_hash_input(&state.request))?
    {
        return Err(bad());
    }
    verify(
        grant.grant.anchor.signing_public_key.as_slice(),
        enrollment_endorsement_message(e),
        &state.endorsement.signature,
    )
}
fn pending(state: &OwnDeviceRequestState) -> AppResult<()> {
    if state.acceptance.is_some() || state.status == OwnDeviceRequestStatus::Accepted {
        return Err(records::conflict());
    }
    Ok(())
}
fn page_limit(limit: u32) -> AppResult<()> {
    if limit == 0 || limit as usize > MAX_PAGE_SIZE {
        return Err(AppError::bad_request("invalid enrollment page limit"));
    }
    Ok(())
}
fn check_live_item(item: &SharedItemState) -> AppResult<()> {
    if item.revision.signed.mutation.operation == SharingOperation::Delete {
        return Err(AppError::gone("shared item deleted"));
    }
    Ok(())
}
async fn lock_context(
    conn: &mut PgConnection,
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    participants: &[(Uuid, Uuid)],
    write: bool,
) -> AppResult<(SharedItemState, BTreeMap<Uuid, DeviceKeys>)> {
    require_enabled(state)?;
    let keys = lock_identities(conn, auth, participants).await?;
    let row = store::lock_item(conn, id.into(), write).await?;
    recheck_session(conn, auth).await?;
    Ok((service::state(&row)?, keys))
}
async fn audit(
    conn: &mut PgConnection,
    auth: &AuthContext,
    share: ShareId,
    event: AuditType,
    meta: serde_json::Value,
) -> AppResult<()> {
    AuditEvent::new(event)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(share)
        .meta(meta)
        .record(conn)
        .await
}

pub async fn publish_grant(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    req: PublishOwnDevicesGrantRequest,
) -> AppResult<SignedSharingOwnDevicesGrantState> {
    require_enabled(state)?;
    validate_signed_grant(&req.grant).map_err(invalid)?;
    let g = &req.grant.grant;
    if g.scope.share_id != id {
        return Err(bad());
    }
    let revoking = g.status == EnrollmentGrantStatus::Revoked;
    let participants = if revoking {
        vec![]
    } else {
        vec![(g.anchor.user_id.into(), g.anchor.device_id.into())]
    };
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &participants, true).await?;
    let access = &item.access.manifest;
    require_owner(access, auth, &keys)?;
    grant_signature(&req.grant, access)?;
    let digest = hash(enrollment_grant_hash_input(&req.grant))?;
    if revoking {
        let old = records::grant(&mut tx, id.into(), g.grant_id).await?;
        grant_signature(&old, access)?;
        if old.grant.status == EnrollmentGrantStatus::Revoked {
            return Err(records::conflict());
        }
        let mut expected = old.grant.clone();
        expected.grant_revision = expected.grant_revision.checked_add(1).ok_or_else(bad)?;
        expected.previous_grant_state_hash = hash(enrollment_grant_hash_input(&old))?.into();
        expected.status = EnrollmentGrantStatus::Revoked;
        if *g != expected {
            return Err(records::conflict());
        }
        records::save_grant(&mut tx, &req.grant, &digest, false).await?;
    } else {
        enabled(state, access)?;
        check_live_item(&item)?;
        if g.grant_revision != 1 {
            return Err(records::conflict());
        }
        active_grant(&req.grant, access)?;
        device_matches(&g.anchor, &keys)?;
        let (total, active): (i64, i64) = sqlx::query_as(
            "SELECT count(*),count(*) FILTER
            (WHERE status='active' AND not_before<=$3 AND expires_at>$3 AND access_manifest_hash=$2)
            FROM shared_enrollment_grants WHERE share_id=$1",
        )
        .bind(Uuid::from(id))
        .bind(g.access_manifest_hash.as_slice())
        .bind(Utc::now().timestamp())
        .fetch_one(&mut *tx)
        .await?;
        if total >= MAX_RETAINED_GRANTS_PER_SHARE as i64 || active >= MAX_GRANTS_PER_SHARE as i64 {
            return Err(AppError::forbidden("enrollment grant quota reached"));
        }
        records::save_grant(&mut tx, &req.grant, &digest, true).await?;
    }
    audit(
        &mut tx,
        auth,
        id,
        AuditType::ShareEnrollmentGrant,
        serde_json::json!({"grant_id":g.grant_id,"revision":g.grant_revision,"revoked":revoking}),
    )
    .await?;
    recheck_session(&mut tx, auth).await?;
    if !revoking {
        current(g.not_before, g.expires_at)?;
    }
    tx.commit().await?;
    Ok(req.grant)
}
fn grant_read_authority(
    state: &AppState,
    access: &AccessManifest,
    auth: &AuthContext,
    keys: &BTreeMap<Uuid, DeviceKeys>,
) -> AppResult<bool> {
    if is_owner(access, auth) {
        require_owner(access, auth, keys)?;
        return Ok(true);
    }
    enabled(state, access)?;
    let member = access
        .members
        .iter()
        .find(|m| m.device_id == auth.device_id && m.user_id == auth.user_id)
        .ok_or_else(AppError::not_found)?;
    service::check_member_keys(member, &keys[&Uuid::from(auth.device_id)])?;
    Ok(false)
}
fn check_anchor_reader(
    grant: &SignedSharingOwnDevicesGrantState,
    auth: &AuthContext,
    keys: &BTreeMap<Uuid, DeviceKeys>,
) -> AppResult<()> {
    if grant.grant.anchor.user_id != auth.user_id || grant.grant.anchor.device_id != auth.device_id
    {
        return Err(AppError::not_found());
    }
    device_matches(&grant.grant.anchor, keys)
}
/// A request target needs only its associated public grant transcript to verify
/// the consumed successor in its acceptance receipt. Membership, request expiry
/// and grant terminal state do not remove that narrow recovery permission.
async fn require_grant_reader(
    conn: &mut PgConnection,
    state: &AppState,
    access: &AccessManifest,
    auth: &AuthContext,
    keys: &BTreeMap<Uuid, DeviceKeys>,
    grant: &SignedSharingOwnDevicesGrantState,
) -> AppResult<()> {
    if is_owner(access, auth) {
        return require_owner(access, auth, keys);
    }
    enabled(state, access)?;
    if grant.grant.anchor.user_id == auth.user_id && grant.grant.anchor.device_id == auth.device_id
    {
        grant_read_authority(state, access, auth, keys)?;
        return check_anchor_reader(grant, auth, keys);
    }
    // Retained requests are bounded per share. Select only the public target
    // bindings, not challenge/response documents. Never authorize by IDs alone:
    // a restored/replaced key under the same device ID must see only a 404.
    let targets: Vec<Json<EnrollmentDeviceBinding>> = sqlx::query_scalar(
        "SELECT document #> '{request,request,target}' FROM shared_enrollment_requests
         WHERE share_id=$1 AND grant_id=$2 AND target_user_id=$3 AND target_device_id=$4",
    )
    .bind(Uuid::from(access.share_id))
    .bind(grant.grant.grant_id)
    .bind(Uuid::from(auth.user_id))
    .bind(Uuid::from(auth.device_id))
    .fetch_all(conn)
    .await?;
    if targets.iter().any(|target| {
        target.user_id == auth.user_id
            && target.device_id == auth.device_id
            && device_matches(target, keys).is_ok()
    }) {
        return Ok(());
    }
    Err(AppError::not_found())
}
pub async fn get_grant(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    grant: Uuid,
) -> AppResult<SignedSharingOwnDevicesGrantState> {
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &[], false).await?;
    let value = records::grant(&mut tx, id.into(), grant).await?;
    require_grant_reader(&mut tx, state, &item.access.manifest, auth, &keys, &value).await?;
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(value)
}
pub async fn list_grants(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    after: Option<Uuid>,
    limit: u32,
) -> AppResult<OwnDevicesGrantPage> {
    page_limit(limit)?;
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &[], false).await?;
    let owner = grant_read_authority(state, &item.access.manifest, auth, &keys)?;
    let rows:Vec<Json<SignedSharingOwnDevicesGrantState>>=sqlx::query_scalar("SELECT document FROM shared_enrollment_grants
        WHERE share_id=$1 AND grant_id>$2 AND ($3 OR (anchor_user_id=$4 AND anchor_device_id=$5)) ORDER BY grant_id LIMIT $6")
        .bind(Uuid::from(id)).bind(after.unwrap_or(Uuid::nil())).bind(owner).bind(Uuid::from(auth.user_id))
        .bind(Uuid::from(auth.device_id)).bind(i64::from(limit)+1).fetch_all(&mut *tx).await?;
    let has_more = rows.len() > limit as usize;
    let items: Vec<_> = rows.into_iter().take(limit as usize).map(|v| v.0).collect();
    if !owner {
        for value in &items {
            check_anchor_reader(value, auth, &keys)?;
        }
    }
    let next_after = if has_more {
        items.last().map(|v| v.grant.grant_id)
    } else {
        None
    };
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(OwnDevicesGrantPage {
        items,
        next_after,
        has_more,
    })
}
pub async fn grant_history(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    grant: Uuid,
    after: u64,
    limit: u32,
) -> AppResult<OwnDevicesGrantHistoryPage> {
    page_limit(limit)?;
    if after > i64::MAX as u64 {
        return Err(bad());
    }
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &[], false).await?;
    let current = records::grant(&mut tx, id.into(), grant).await?;
    require_grant_reader(&mut tx, state, &item.access.manifest, auth, &keys, &current).await?;
    if after > current.grant.grant_revision {
        return Err(records::conflict());
    }
    let rows: Vec<Json<SignedSharingOwnDevicesGrantState>> = sqlx::query_scalar(
        "SELECT document FROM shared_enrollment_grant_states
        WHERE share_id=$1 AND grant_id=$2 AND revision>$3 ORDER BY revision LIMIT $4",
    )
    .bind(Uuid::from(id))
    .bind(grant)
    .bind(after as i64)
    .bind(i64::from(limit))
    .fetch_all(&mut *tx)
    .await?;
    let has_more = after + (rows.len() as u64) < current.grant.grant_revision;
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(OwnDevicesGrantHistoryPage {
        states: rows.into_iter().map(|v| v.0).collect(),
        latest_revision: current.grant.grant_revision,
        has_more,
    })
}

async fn snapshot_request(
    state: &AppState,
    id: ShareId,
    request: Uuid,
) -> AppResult<OwnDeviceRequestState> {
    require_enabled(state)?;
    let mut conn = state.db.acquire().await?;
    records::request(&mut conn, id.into(), request).await
}
async fn snapshot_grant(
    state: &AppState,
    id: ShareId,
    grant: Uuid,
) -> AppResult<SignedSharingOwnDevicesGrantState> {
    require_enabled(state)?;
    let mut conn = state.db.acquire().await?;
    records::grant(&mut conn, id.into(), grant).await
}
fn identities(
    grant: &SignedSharingOwnDevicesGrantState,
    request: &SharingOwnDeviceRequest,
) -> Vec<(Uuid, Uuid)> {
    vec![
        (
            grant.grant.owner_user_id.into(),
            grant.grant.owner_device_id.into(),
        ),
        (
            grant.grant.anchor.user_id.into(),
            grant.grant.anchor.device_id.into(),
        ),
        (
            request.target.user_id.into(),
            request.target.device_id.into(),
        ),
    ]
}
pub async fn submit_request(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    req: SubmitOwnDeviceRequest,
) -> AppResult<OwnDeviceRequestState> {
    require_enabled(state)?;
    validate_submission(&req).map_err(invalid)?;
    let r = &req.request.request;
    if r.scope.share_id != id {
        return Err(bad());
    }
    if r.target.user_id != auth.user_id || r.target.device_id != auth.device_id {
        return Err(AppError::not_found());
    }
    let before = snapshot_grant(state, id, req.grant_id).await?;
    if before.grant.anchor.user_id != auth.user_id {
        return Err(AppError::not_found());
    }
    let participants = identities(&before, r);
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &participants, true).await?;
    let access = &item.access.manifest;
    enabled(state, access)?;
    check_live_item(&item)?;
    let grant = records::grant(&mut tx, id.into(), req.grant_id).await?;
    if grant.grant.anchor != before.grant.anchor {
        return Err(records::conflict());
    }
    service::check_member_keys(
        owner_key(access)?,
        keys.get(&Uuid::from(access.owner_device_id))
            .ok_or_else(bad)?,
    )?;
    device_matches(&grant.grant.anchor, &keys)?;
    device_matches(&r.target, &keys)?;
    let value = OwnDeviceRequestState {
        grant_id: req.grant_id,
        request: req.request,
        endorsement: req.endorsement,
        status: OwnDeviceRequestStatus::Pending,
        challenge: None,
        response: None,
        acceptance: None,
    };
    submission(&grant, &value, access)?;
    let (pending_share, pending_grant): (i64, i64) = sqlx::query_as(
        "SELECT count(*),count(*) FILTER (WHERE r.grant_id=$2)
        FROM shared_enrollment_requests r JOIN shared_enrollment_grants g
        ON g.share_id=r.share_id AND g.grant_id=r.grant_id
        WHERE r.share_id=$1 AND NOT r.accepted AND r.expires_at>$3
        AND g.status='active' AND g.not_before<=$3 AND g.expires_at>$3
        AND g.state_hash=r.grant_state_hash AND g.access_manifest_hash=$4",
    )
    .bind(Uuid::from(id))
    .bind(value.grant_id)
    .bind(Utc::now().timestamp())
    .bind(service::manifest_hash(access)?.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM shared_enrollment_requests WHERE share_id=$1")
            .bind(Uuid::from(id))
            .fetch_one(&mut *tx)
            .await?;
    if total >= MAX_RETAINED_REQUESTS_PER_SHARE as i64
        || pending_share >= MAX_PENDING_REQUESTS_PER_SHARE as i64
        || pending_grant >= MAX_PENDING_REQUESTS_PER_GRANT as i64
    {
        return Err(AppError::forbidden("enrollment request quota reached"));
    }
    records::insert_request(
        &mut tx,
        &value,
        &hash(enrollment_request_hash_input(&value.request))?,
    )
    .await?;
    audit(&mut tx,auth,id,AuditType::ShareEnrollmentRequest,serde_json::json!({"grant_id":value.grant_id,"request_id":value.request.request.request_id})).await?;
    current(
        value.request.request.not_before,
        value.request.request.expires_at,
    )?;
    current(grant.grant.not_before, grant.grant.expires_at)?;
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(value)
}
async fn display_status(
    conn: &mut PgConnection,
    item: &SharedItemState,
    mut value: OwnDeviceRequestState,
) -> AppResult<OwnDeviceRequestState> {
    if value.status == OwnDeviceRequestStatus::Accepted {
        return Ok(value);
    }
    let r = &value.request.request;
    if Utc::now().timestamp() >= r.expires_at {
        value.status = OwnDeviceRequestStatus::Expired;
        return Ok(value);
    }
    let grant = records::grant(conn, r.scope.share_id.into(), value.grant_id).await?;
    if grant.grant.status == EnrollmentGrantStatus::Revoked
        || r.grant_state_hash.as_slice() != hash(enrollment_grant_hash_input(&grant))?
        || r.access_manifest_hash.as_slice() != service::manifest_hash(&item.access.manifest)?
        || item.revision.signed.mutation.operation == SharingOperation::Delete
    {
        value.status = OwnDeviceRequestStatus::Denied;
    }
    Ok(value)
}
pub async fn get_request(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    request: Uuid,
) -> AppResult<OwnDeviceRequestState> {
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &[], false).await?;
    enabled(state, &item.access.manifest)?;
    let value = records::request(&mut tx, id.into(), request).await?;
    if is_owner(&item.access.manifest, auth) {
        require_owner(&item.access.manifest, auth, &keys)?;
    } else {
        let target = &value.request.request.target;
        if target.user_id != auth.user_id || target.device_id != auth.device_id {
            return Err(AppError::not_found());
        }
        device_matches(target, &keys)?;
    }
    let value = display_status(&mut tx, &item, value).await?;
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(value)
}
pub async fn list_requests(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    after: Option<Uuid>,
    limit: u32,
) -> AppResult<OwnDeviceRequestPage> {
    page_limit(limit)?;
    let mut tx = state.db.begin().await?;
    let (item, keys) = lock_context(&mut tx, state, auth, id, &[], false).await?;
    enabled(state, &item.access.manifest)?;
    require_owner(&item.access.manifest, auth, &keys)?;
    let rows: Vec<Json<OwnDeviceRequestState>> = sqlx::query_scalar(
        "SELECT document FROM shared_enrollment_requests
        WHERE share_id=$1 AND request_id>$2 ORDER BY request_id LIMIT $3",
    )
    .bind(Uuid::from(id))
    .bind(after.unwrap_or(Uuid::nil()))
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut *tx)
    .await?;
    let has_more = rows.len() > limit as usize;
    let mut items = Vec::new();
    for row in rows.into_iter().take(limit as usize) {
        items.push(display_status(&mut tx, &item, row.0).await?);
    }
    let next_after = if has_more {
        items.last().map(|v| v.request.request.request_id)
    } else {
        None
    };
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(OwnDeviceRequestPage {
        items,
        next_after,
        has_more,
    })
}
async fn request_context(
    conn: &mut PgConnection,
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    snapshot: &OwnDeviceRequestState,
    before: &SignedSharingOwnDevicesGrantState,
    owner: bool,
) -> AppResult<(
    SharedItemState,
    OwnDeviceRequestState,
    SignedSharingOwnDevicesGrantState,
)> {
    // Reject unrelated callers before participant liveness or tombstone checks
    // can disclose anything about a request identified by a guessed UUID.
    let expected = if owner {
        (before.grant.owner_user_id, before.grant.owner_device_id)
    } else {
        (
            snapshot.request.request.target.user_id,
            snapshot.request.request.target.device_id,
        )
    };
    if expected != (auth.user_id, auth.device_id) {
        return Err(AppError::not_found());
    }
    let participants = identities(before, &snapshot.request.request);
    let (item, keys) = lock_context(conn, state, auth, id, &participants, true).await?;
    let access = &item.access.manifest;
    enabled(state, access)?;
    check_live_item(&item)?;
    let value = records::request(conn, id.into(), snapshot.request.request.request_id).await?;
    if value.grant_id != snapshot.grant_id
        || value.request != snapshot.request
        || value.endorsement != snapshot.endorsement
    {
        return Err(records::conflict());
    }
    if owner {
        require_owner(access, auth, &keys)?;
    } else if value.request.request.target.user_id != auth.user_id
        || value.request.request.target.device_id != auth.device_id
    {
        return Err(AppError::not_found());
    }
    let grant = records::grant(conn, id.into(), value.grant_id).await?;
    if grant.grant.anchor != before.grant.anchor {
        return Err(records::conflict());
    }
    service::check_member_keys(
        owner_key(access)?,
        keys.get(&Uuid::from(access.owner_device_id))
            .ok_or_else(bad)?,
    )?;
    device_matches(&grant.grant.anchor, &keys)?;
    device_matches(&value.request.request.target, &keys)?;
    pending(&value)?;
    submission(&grant, &value, access)?;
    Ok((item, value, grant))
}
fn transcript_challenge(value: &OwnDeviceRequestState, access: &AccessManifest) -> AppResult<()> {
    let signed = value.challenge.as_ref().ok_or_else(records::conflict)?;
    let c = &signed.challenge;
    validate_challenge_for_request(c, &value.request.request).map_err(invalid)?;
    if c.request_hash.as_slice() != hash(enrollment_request_hash_input(&value.request))?
        || c.anchor_endorsement_hash.as_slice()
            != hash(enrollment_endorsement_hash_input(&value.endorsement))?
        || !crypto::is_valid_encryption_public_key(c.ephemeral_public_key.as_slice())
    {
        return Err(bad());
    }
    verify(
        owner_key(access)?.signing_public_key.as_slice(),
        enrollment_challenge_message(c),
        &signed.signature,
    )?;
    current(c.not_before, c.expires_at)
}
fn transcript_response(value: &OwnDeviceRequestState) -> AppResult<()> {
    let signed = value.response.as_ref().ok_or_else(records::conflict)?;
    let response = &signed.response;
    if response.request_hash.as_slice() != hash(enrollment_request_hash_input(&value.request))?
        || response.challenge_hash.as_slice()
            != hash(enrollment_challenge_hash_input(
                value.challenge.as_ref().ok_or_else(records::conflict)?,
            ))?
    {
        return Err(bad());
    }
    verify(
        value.request.request.target.signing_public_key.as_slice(),
        enrollment_response_message(response),
        &signed.signature,
    )
}
/// A request is at most15 minutes old; bound retained generation metadata too.
const MAX_CHALLENGE_GENERATIONS: u64 = 64;
pub async fn publish_challenge(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    request: Uuid,
    req: PublishOwnDeviceChallengeRequest,
) -> AppResult<OwnDeviceRequestState> {
    validate_signed_challenge(&req.challenge).map_err(invalid)?;
    let snapshot = snapshot_request(state, id, request).await?;
    let before = snapshot_grant(state, id, snapshot.grant_id).await?;
    let mut tx = state.db.begin().await?;
    let (item, mut value, grant) =
        request_context(&mut tx, state, auth, id, &snapshot, &before, true).await?;
    let next_generation = value
        .challenge
        .as_ref()
        .map_or(Some(1), |c| c.challenge.generation.checked_add(1))
        .ok_or_else(bad)?;
    if req.challenge.challenge.generation != next_generation {
        return Err(records::conflict());
    }
    if next_generation > MAX_CHALLENGE_GENERATIONS {
        return Err(AppError::forbidden("enrollment challenge quota reached"));
    }
    value.challenge = Some(req.challenge);
    value.response = None;
    value.status = OwnDeviceRequestStatus::Challenged;
    transcript_challenge(&value, &item.access.manifest)?;
    records::remember_challenge(
        &mut tx,
        id.into(),
        request,
        value.challenge.as_ref().ok_or_else(bad)?,
    )
    .await?;
    records::save_request(&mut tx, &value).await?;
    audit(
        &mut tx,
        auth,
        id,
        AuditType::ShareEnrollmentChallenge,
        serde_json::json!({"request_id":request,"generation":next_generation}),
    )
    .await?;
    current(grant.grant.not_before, grant.grant.expires_at)?;
    current(
        value.request.request.not_before,
        value.request.request.expires_at,
    )?;
    let c = &value.challenge.as_ref().ok_or_else(bad)?.challenge;
    current(c.not_before, c.expires_at)?;
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(value)
}
pub async fn submit_response(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    request: Uuid,
    req: SubmitOwnDeviceChallengeResponseRequest,
) -> AppResult<OwnDeviceRequestState> {
    validate_signed_response(&req.response).map_err(invalid)?;
    let snapshot = snapshot_request(state, id, request).await?;
    let before = snapshot_grant(state, id, snapshot.grant_id).await?;
    let mut tx = state.db.begin().await?;
    let (item, mut value, grant) =
        request_context(&mut tx, state, auth, id, &snapshot, &before, false).await?;
    if value.response.is_some() {
        return Err(records::conflict());
    }
    transcript_challenge(&value, &item.access.manifest)?;
    value.response = Some(req.response);
    value.status = OwnDeviceRequestStatus::Responded;
    transcript_response(&value)?;
    records::save_request(&mut tx, &value).await?;
    audit(
        &mut tx,
        auth,
        id,
        AuditType::ShareEnrollmentResponse,
        serde_json::json!({"request_id":request}),
    )
    .await?;
    current(grant.grant.not_before, grant.grant.expires_at)?;
    current(
        value.request.request.not_before,
        value.request.request.expires_at,
    )?;
    let c = &value.challenge.as_ref().ok_or_else(bad)?.challenge;
    current(c.not_before, c.expires_at)?;
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(value)
}

/// Acceptance shares the ordinary rotation transaction and lock order. The
/// provisional v1 writes are rolled back if any enrollment proof fails.
pub async fn accept_request(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    request_id: Uuid,
    req: AcceptOwnDeviceRequest,
) -> AppResult<OwnDeviceAcceptanceResult> {
    require_enabled(state)?;
    validate_accept_request(&req).map_err(invalid)?;
    enabled(state, &req.rotation.access.manifest)?;
    let mut tx = state.db.begin().await?;
    // This must be the first locking operation: users/devices/session, then
    // item. No enrollment path may acquire identity locks after the item.
    let (old, next) =
        service::rotate_in_transaction(&mut tx, state, auth, id, req.rotation.clone()).await?;
    let previous = &old.access.manifest;
    let access = &next.access.manifest;
    enabled(state, previous)?;
    check_live_item(&old)?;
    let mut value = records::request(&mut tx, id.into(), request_id).await?;
    pending(&value)?;
    let grant = records::grant(&mut tx, id.into(), value.grant_id).await?;
    submission(&grant, &value, previous)?;
    let request = &value.request.request;
    // Preserve every old member, role and key. Exactly one target is added.
    // Consequently v1 rotation has already locked/checked all proof identities.
    if access.members.len() != previous.members.len() + 1
        || previous
            .members
            .iter()
            .any(|member| !access.members.contains(member))
        || !access.members.iter().any(|member| {
            member_matches(member, &request.target) && member.role == request.requested_role
        })
    {
        return Err(bad());
    }
    transcript_challenge(&value, previous)?;
    transcript_response(&value)?;
    let receipt = &req.acceptance.acceptance;
    let challenge = value.challenge.as_ref().ok_or_else(records::conflict)?;
    let response = value.response.as_ref().ok_or_else(records::conflict)?;
    let revision_message =
        cc_protocol::sharing::sharing_mutation_message(&next.revision.signed.mutation)
            .map_err(|_| bad())?;
    if receipt.request_hash.as_slice() != hash(enrollment_request_hash_input(&value.request))?
        || receipt.anchor_endorsement_hash.as_slice()
            != hash(enrollment_endorsement_hash_input(&value.endorsement))?
        || receipt.challenge_hash.as_slice() != hash(enrollment_challenge_hash_input(challenge))?
        || receipt.response_hash.as_slice() != hash(enrollment_response_hash_input(response))?
        || receipt.consumed_grant_state_hash.as_slice()
            != hash(enrollment_grant_hash_input(&grant))?
        || receipt.result_access_manifest_hash.as_slice() != service::manifest_hash(access)?
        || receipt.result_revision_hash.as_slice() != crypto::sha256(&revision_message)
        || receipt.consumed_grant_successor_hash.as_slice()
            != hash(enrollment_grant_hash_input(&req.consumed_grant_successor))?
    {
        return Err(bad());
    }
    verify(
        owner_key(previous)?.signing_public_key.as_slice(),
        enrollment_acceptance_message(receipt),
        &req.acceptance.signature,
    )?;
    check_successor(&grant, &req.consumed_grant_successor, access, true)?;
    let mut old_others = Vec::new();
    for successor in &req.other_grant_successors {
        let before = records::grant(&mut tx, id.into(), successor.grant.grant_id).await?;
        active_grant(&before, previous)?;
        check_successor(&before, successor, access, false)?;
        let signed_hash = hash(enrollment_grant_hash_input(successor))?;
        if !receipt.other_grant_successor_hashes.iter().any(|entry| {
            entry.grant_id == successor.grant.grant_id && entry.state_hash.as_slice() == signed_hash
        }) {
            return Err(bad());
        }
        old_others.push(before);
    }
    for successor in
        std::iter::once(&req.consumed_grant_successor).chain(req.other_grant_successors.iter())
    {
        records::save_grant(
            &mut tx,
            successor,
            &hash(enrollment_grant_hash_input(successor))?,
            false,
        )
        .await?;
    }
    value.acceptance = Some(req.acceptance.clone());
    value.status = OwnDeviceRequestStatus::Accepted;
    records::save_request(&mut tx, &value).await?;
    audit(
        &mut tx,
        auth,
        id,
        AuditType::ShareEnrollmentAccepted,
        serde_json::json!({"request_id":request_id,"grant_id":value.grant_id,
            "admitted_count":req.consumed_grant_successor.grant.admitted_count}),
    )
    .await?;
    // Lock waits and writes must not turn an expired transcript into authority.
    current(grant.grant.not_before, grant.grant.expires_at)?;
    current(
        value.request.request.not_before,
        value.request.request.expires_at,
    )?;
    let challenge = &value.challenge.as_ref().ok_or_else(bad)?.challenge;
    current(challenge.not_before, challenge.expires_at)?;
    for before in &old_others {
        current(before.grant.not_before, before.grant.expires_at)?;
    }
    recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(OwnDeviceAcceptanceResult {
        state: next,
        acceptance: req.acceptance,
        consumed_grant_successor: req.consumed_grant_successor,
        other_grant_successors: req.other_grant_successors,
    })
}

fn check_successor(
    before: &SignedSharingOwnDevicesGrantState,
    after: &SignedSharingOwnDevicesGrantState,
    access: &AccessManifest,
    consumed: bool,
) -> AppResult<()> {
    grant_signature(after, access)?;
    let mut expected = before.grant.clone();
    expected.grant_revision = expected.grant_revision.checked_add(1).ok_or_else(bad)?;
    expected.previous_grant_state_hash = hash(enrollment_grant_hash_input(before))?.into();
    expected.access_manifest_hash = service::manifest_hash(access)?.into();
    expected.access_epoch = access.access_epoch;
    if consumed {
        expected.admitted_count = expected.admitted_count.checked_add(1).ok_or_else(bad)?;
        expected.status = after.grant.status;
    }
    if after.grant != expected {
        return Err(records::conflict());
    }
    Ok(())
}
