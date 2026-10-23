// SPDX-License-Identifier: AGPL-3.0-only
//! Signed SharedItem transitions; the database remains ciphertext-only.
use super::{
    auth::lock_identities,
    require_enabled,
    store::{self, StoredItem},
};
use crate::{
    auth::AuthContext,
    config::Config,
    crypto,
    error::{AppError, AppResult},
    AppState,
};
use cc_protocol::{sharing::*, ErrorCode, ShareId};
use sqlx::{types::Json, PgConnection};
use std::collections::BTreeSet;
use uuid::Uuid;

fn invalid(_: SharingValidationError) -> AppError {
    AppError::bad_request("invalid sharing payload")
}
fn owner_only() -> AppError {
    AppError::new(
        ErrorCode::OwnerOnly,
        "only the owner may delete a shared item; leave the share instead",
    )
}
/// Items a user owns that still occupy storage: live or restorable.
const MAX_OWNED_ITEMS: i64 = 1000;
/// Hard bound on all rows of one owner, including expired tombstones.
const MAX_OWNED_ROWS: i64 = 10_000;
fn conflict() -> AppError {
    AppError::new(
        ErrorCode::Conflict,
        "sharing state changed; fetch latest state",
    )
}
pub(super) fn state(row: &StoredItem) -> AppResult<SharedItemState> {
    Ok(SharedItemState {
        access: serde_json::from_value(row.current_manifest.0.clone())
            .map_err(|_| AppError::internal("stored sharing manifest invalid"))?,
        revision: serde_json::from_value(row.current_mutation.0.clone())
            .map_err(|_| AppError::internal("stored sharing revision invalid"))?,
    })
}
fn bindings(m: &AccessManifest) -> Vec<(Uuid, Uuid)> {
    m.members
        .iter()
        .map(|v| (v.user_id.into(), v.device_id.into()))
        .collect()
}
pub(super) fn member<'a>(
    m: &'a AccessManifest,
    auth: &AuthContext,
) -> AppResult<&'a SharingMember> {
    m.members
        .iter()
        .find(|v| v.device_id == auth.device_id && v.user_id == auth.user_id)
        .ok_or_else(AppError::not_found)
}
pub(super) fn manifest_hash(m: &AccessManifest) -> AppResult<[u8; 32]> {
    Ok(crypto::sha256(
        &sharing_manifest_message(m).map_err(invalid)?,
    ))
}
pub(super) fn check_member_keys(
    m: &SharingMember,
    keys: &super::auth::DeviceKeys,
) -> AppResult<()> {
    if Uuid::from(m.user_id) != keys.user_id
        || m.encryption_public_key.as_slice() != keys.encryption
        || m.signing_public_key.as_slice() != keys.signing
    {
        return Err(AppError::invalid_proof("sharing device keys changed"));
    }
    Ok(())
}
pub(super) fn kind_enabled(config: &Config, kind: SharedItemKind) -> bool {
    match kind {
        SharedItemKind::Host | SharedItemKind::Snippet => true,
        SharedItemKind::Group => config.shared_groups_enabled,
        SharedItemKind::Secret => config.shared_secrets_enabled,
        SharedItemKind::KubeContext => config.shared_kube_contexts_enabled,
        SharedItemKind::DbConnection => config.shared_db_connections_enabled,
    }
}

/// Additional kinds are opt-in per request so older clients keep their baseline.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListKinds {
    pub include_groups: bool,
    pub include_secrets: bool,
    pub include_kube_contexts: bool,
    pub include_db_connections: bool,
}
impl ListKinds {
    fn includes(self, kind: SharedItemKind) -> bool {
        match kind {
            SharedItemKind::Host | SharedItemKind::Snippet => true,
            SharedItemKind::Group => self.include_groups,
            SharedItemKind::Secret => self.include_secrets,
            SharedItemKind::KubeContext => self.include_kube_contexts,
            SharedItemKind::DbConnection => self.include_db_connections,
        }
    }
    fn validate(self, config: &Config) -> AppResult<()> {
        if (self.include_groups && !config.shared_groups_enabled)
            || (self.include_secrets && !config.shared_secrets_enabled)
            || (self.include_kube_contexts && !config.shared_kube_contexts_enabled)
            || (self.include_db_connections && !config.shared_db_connections_enabled)
        {
            return Err(AppError::bad_request("requested sharing kind not enabled"));
        }
        Ok(())
    }
}

fn check_access(config: &Config, access: &SignedAccessManifest) -> AppResult<()> {
    let message = sharing_manifest_message(&access.manifest).map_err(invalid)?;
    if !kind_enabled(config, access.manifest.kind) {
        return Err(AppError::bad_request("sharing content kind not enabled"));
    }
    let owner = access
        .manifest
        .members
        .iter()
        .find(|v| v.device_id == access.manifest.owner_device_id)
        .ok_or_else(|| AppError::bad_request("sharing owner missing"))?;
    if !crypto::verify_ed25519(
        owner.signing_public_key.as_slice(),
        &message,
        access.signature.as_slice(),
    ) {
        return Err(AppError::invalid_proof("invalid sharing owner signature"));
    }
    Ok(())
}
fn check_revision(
    access: &AccessManifest,
    revision: &SharedRevision,
    auth: &AuthContext,
) -> AppResult<[u8; 32]> {
    let m = &revision.signed.mutation;
    let message = sharing_mutation_message(m).map_err(invalid)?;
    let writer = member(access, auth)?;
    if !writer.role.can_write() {
        return Err(AppError::forbidden("sharing editor role required"));
    }
    if m.writer_device_id != auth.device_id
        || m.context.server_instance_id != access.server_instance_id
        || m.context.share_id != access.share_id
        || m.context.item_id != access.item_id
        || m.context.kind != access.kind
        || m.context.access_epoch != access.access_epoch
        || m.manifest_revision != access.revision
        || m.manifest_hash.as_slice() != manifest_hash(access)?
    {
        return Err(AppError::bad_request("sharing revision binding mismatch"));
    }
    if !crypto::verify_ed25519(
        writer.signing_public_key.as_slice(),
        &message,
        revision.signed.signature.as_slice(),
    ) {
        return Err(AppError::invalid_proof("invalid sharing writer signature"));
    }
    match (&revision.body, m.operation) {
        (Some(body), SharingOperation::Put) => {
            let message = sharing_body_message(body).map_err(invalid)?;
            if m.body_hash.as_slice() != crypto::sha256(&message) {
                return Err(AppError::invalid_proof("sharing body hash mismatch"));
            }
            let expected: BTreeSet<_> = access.members.iter().map(|v| v.device_id).collect();
            let actual: BTreeSet<_> = body
                .envelopes
                .iter()
                .map(|v| v.recipient_device_id)
                .collect();
            if expected != actual {
                return Err(AppError::bad_request("sharing envelope coverage mismatch"));
            }
            if body
                .envelopes
                .iter()
                .any(|e| !crypto::is_valid_encryption_public_key(e.ephemeral_public_key.as_slice()))
            {
                return Err(AppError::bad_request("invalid sharing envelope key"));
            }
        }
        (None, SharingOperation::Delete) => {}
        _ => return Err(AppError::bad_request("sharing body operation mismatch")),
    }
    Ok(crypto::sha256(&message))
}
fn check_fresh_body(old: &SharedRevision, new: &SharedRevision) -> AppResult<()> {
    if let (Some(old), Some(new)) = (&old.body, &new.body) {
        if old.ciphertext == new.ciphertext
            || old.nonce == new.nonce
            || new.envelopes.iter().any(|n| {
                old.envelopes.iter().any(|o| {
                    n.recipient_device_id == o.recipient_device_id
                        && (n.ciphertext == o.ciphertext
                            || n.ephemeral_public_key == o.ephemeral_public_key)
                })
            })
        {
            return Err(AppError::bad_request(
                "sharing revision requires fresh ciphertext and envelopes",
            ));
        }
    }
    Ok(())
}
async fn check_instance(conn: &mut PgConnection, instance: Uuid) -> AppResult<()> {
    let expected: Uuid =
        sqlx::query_scalar("SELECT instance_id FROM sharing_instance WHERE singleton")
            .fetch_one(conn)
            .await?;
    if instance != expected {
        return Err(AppError::bad_request("sharing server instance mismatch"));
    }
    Ok(())
}
/// Recipients who left stay outside the device ACL until the owner's next
/// signed manifest drops them (acknowledged) or adds a device of theirs the
/// previous manifest did not have (an explicit new invitation).
async fn settle_departures(
    conn: &mut PgConnection,
    previous: &AccessManifest,
    next: &AccessManifest,
) -> AppResult<BTreeSet<Uuid>> {
    let departed: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM shared_item_departures WHERE share_id=$1")
            .bind(Uuid::from(next.share_id))
            .fetch_all(&mut *conn)
            .await?;
    let old_devices: BTreeSet<_> = previous.members.iter().map(|v| v.device_id).collect();
    let mut still = BTreeSet::new();
    for user in departed {
        let devices: Vec<_> = next
            .members
            .iter()
            .filter(|v| Uuid::from(v.user_id) == user)
            .collect();
        if devices.is_empty() || devices.iter().any(|v| !old_devices.contains(&v.device_id)) {
            sqlx::query("DELETE FROM shared_item_departures WHERE share_id=$1 AND user_id=$2")
                .bind(Uuid::from(next.share_id))
                .bind(user)
                .execute(&mut *conn)
                .await?;
        } else {
            still.insert(user);
        }
    }
    Ok(still)
}
async fn persist(
    conn: &mut PgConnection,
    access: &SignedAccessManifest,
    revision: &SharedRevision,
    revision_hash: [u8; 32],
    creating: bool,
    previous: Option<&AccessManifest>,
) -> AppResult<()> {
    let manifest_changed = creating || previous.is_some();
    let m = &access.manifest;
    let row = StoredItem {
        id: m.share_id.into(),
        owner_user_id: m.owner_user_id.into(),
        owner_device_id: m.owner_device_id.into(),
        revision: revision.signed.mutation.context.revision,
        access_epoch: m.access_epoch as i64,
        manifest_revision: m.revision as i64,
        manifest_hash: manifest_hash(m)?.to_vec(),
        revision_hash: revision_hash.to_vec(),
        deleted: revision.signed.mutation.operation == SharingOperation::Delete,
        current_manifest: Json(
            serde_json::to_value(access)
                .map_err(|_| AppError::internal("sharing serialization failed"))?,
        ),
        current_mutation: Json(
            serde_json::to_value(revision)
                .map_err(|_| AppError::internal("sharing serialization failed"))?,
        ),
    };
    let duplicate: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM shared_revision_headers WHERE share_id=$1 AND mutation_id=$2)",
    )
    .bind(row.id)
    .bind(Uuid::from(revision.signed.mutation.mutation_id))
    .fetch_one(&mut *conn)
    .await?;
    if duplicate {
        return Err(conflict());
    }
    let departed = match previous {
        Some(previous) if !creating => settle_departures(conn, previous, m).await?,
        _ => BTreeSet::new(),
    };
    let members: Vec<_> = m
        .members
        .iter()
        .filter(|v| !departed.contains(&Uuid::from(v.user_id)))
        .map(|v| {
            (
                v.user_id.into(),
                v.device_id.into(),
                if v.role.can_write() { "edit" } else { "read" },
            )
        })
        .collect();
    store::save(conn, &row, &members, creating, manifest_changed).await?;
    sqlx::query("INSERT INTO shared_revision_headers (share_id,revision,mutation_id,document) VALUES ($1,$2,$3,$4)")
        .bind(row.id).bind(row.revision).bind(Uuid::from(revision.signed.mutation.mutation_id))
        .bind(Json(&revision.signed)).execute(&mut *conn).await?;
    let writer = m
        .members
        .iter()
        .find(|v| v.device_id == revision.signed.mutation.writer_device_id)
        .ok_or_else(|| AppError::internal("sharing writer missing"))?;
    use crate::audit::{AuditEvent, AuditType};
    AuditEvent::new(if creating { AuditType::ShareCreated } else if manifest_changed { AuditType::ShareAccessRotated } else { AuditType::ShareRevision })
        .user(writer.user_id).device(writer.device_id).target(m.share_id)
        .meta(serde_json::json!({ "revision": row.revision, "access_epoch": row.access_epoch, "members": members.len(), "deleted": row.deleted }))
        .record(conn).await?;
    Ok(())
}

pub async fn create(
    state: &AppState,
    auth: &AuthContext,
    req: CreateShareRequest,
) -> AppResult<SharedItemState> {
    require_enabled(state)?;
    state
        .rate
        .account(state, crate::config::Limit::ShareWriteAccount, auth.user_id)
        .await?;
    if state.config.require_email_verification && !auth.email_verified {
        return Err(AppError::new(
            ErrorCode::EmailNotVerified,
            "verify email before creating a shared item",
        ));
    }
    check_access(&state.config, &req.access)?;
    let m = &req.access.manifest;
    if m.owner_user_id != auth.user_id || m.owner_device_id != auth.device_id {
        return Err(AppError::forbidden("authenticated owner device required"));
    }
    if m.revision != 1 || req.revision.signed.mutation.base_revision != 0 {
        return Err(AppError::bad_request("sharing genesis required"));
    }
    let hash = check_revision(m, &req.revision, auth)?;
    let mut tx = state.db.begin().await?;
    let keys = lock_identities(&mut tx, auth, &bindings(m)).await?;
    for v in &m.members {
        check_member_keys(v, &keys[&Uuid::from(v.device_id)])?;
    }
    check_instance(&mut tx, m.server_instance_id).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("sharing-owner:{}", auth.user_id))
        .execute(&mut *tx)
        .await?;
    let restoring = match req.restored_from {
        Some(from) => Some(take_restorable(&mut tx, auth, from, m).await?),
        None => None,
    };
    // Expired tombstones no longer count; a restore replaces its own entry.
    let (live, rows): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE NOT deleted OR restore_revision IS NOT NULL), count(*)
         FROM shared_items WHERE owner_user_id=$1",
    )
    .bind(Uuid::from(auth.user_id))
    .fetch_one(&mut *tx)
    .await?;
    if live - i64::from(restoring.is_some()) >= MAX_OWNED_ITEMS || rows >= MAX_OWNED_ROWS {
        return Err(AppError::forbidden("shared item quota reached"));
    }
    persist(&mut tx, &req.access, &req.revision, hash, true, None).await?;
    if let Some(from) = restoring {
        sqlx::query("UPDATE shared_items SET restore_revision=NULL WHERE id=$1")
            .bind(from)
            .execute(&mut *tx)
            .await?;
        use crate::audit::{AuditEvent, AuditType};
        AuditEvent::new(AuditType::ShareRestored)
            .user(auth.user_id)
            .device(auth.device_id)
            .target(m.share_id)
            .meta(serde_json::json!({ "restored_from": from }))
            .record(&mut *tx)
            .await?;
    }
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(SharedItemState {
        access: req.access,
        revision: req.revision,
    })
}

/// Checks a `restored_from` reference inside the create transaction (after
/// identity locks) and returns the locked deleted item's id.
async fn take_restorable(
    conn: &mut PgConnection,
    auth: &AuthContext,
    from: ShareId,
    next: &AccessManifest,
) -> AppResult<Uuid> {
    if from == next.share_id {
        return Err(AppError::bad_request("invalid sharing restore source"));
    }
    let old = store::lock_item(&mut *conn, from.into(), true).await?;
    if old.owner_user_id != Uuid::from(auth.user_id) {
        return Err(AppError::not_found());
    }
    let restorable: bool = sqlx::query_scalar(
        "SELECT deleted AND restore_revision IS NOT NULL
                AND deleted_at > clock_timestamp() - make_interval(days => $2)
         FROM shared_items WHERE id=$1",
    )
    .bind(old.id)
    .bind(RESTORE_WINDOW_DAYS as i32)
    .fetch_one(&mut *conn)
    .await?;
    if !restorable {
        return Err(AppError::gone("shared item is not restorable"));
    }
    if state(&old)?.access.manifest.kind != next.kind {
        return Err(AppError::bad_request("sharing restore kind mismatch"));
    }
    let departed: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM shared_item_departures WHERE share_id=$1")
            .bind(old.id)
            .fetch_all(&mut *conn)
            .await?;
    if next
        .members
        .iter()
        .any(|v| departed.contains(&Uuid::from(v.user_id)))
    {
        return Err(AppError::forbidden(
            "a recipient who left cannot be added back by a restore",
        ));
    }
    Ok(old.id)
}

pub async fn put(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    req: PutSharedRevisionRequest,
) -> AppResult<SharedItemState> {
    transition(state, auth, id, None, req.revision).await
}
pub async fn rotate(
    state: &AppState,
    auth: &AuthContext,
    id: ShareId,
    req: RotateShareAccessRequest,
) -> AppResult<SharedItemState> {
    transition(state, auth, id, Some(req.access), req.revision).await
}
async fn transition(
    state_: &AppState,
    auth: &AuthContext,
    id: ShareId,
    access: Option<SignedAccessManifest>,
    revision: SharedRevision,
) -> AppResult<SharedItemState> {
    require_enabled(state_)?;
    state_
        .rate
        .account(
            state_,
            crate::config::Limit::ShareRevisionAccount,
            auth.user_id,
        )
        .await?;
    let mut tx = state_.db.begin().await?;
    let (_, next) = transition_in_transaction(&mut tx, state_, auth, id, access, revision).await?;
    tx.commit().await?;
    Ok(next)
}

/// Enrollment calls this FIRST in its transaction, before any item/child lock.
/// It locks all next-manifest identities then the item, applies the ordinary v1
/// rotation provisionally and returns both states. Enrollment checks/receipt and
/// grant successors commit in the same caller-owned transaction; any error rolls
/// the whole rotation back. The caller never acquires new identity locks later.
pub(super) async fn rotate_in_transaction(
    conn: &mut PgConnection,
    state_: &AppState,
    auth: &AuthContext,
    id: ShareId,
    req: RotateShareAccessRequest,
) -> AppResult<(SharedItemState, SharedItemState)> {
    transition_in_transaction(conn, state_, auth, id, Some(req.access), req.revision).await
}

async fn transition_in_transaction(
    conn: &mut PgConnection,
    state_: &AppState,
    auth: &AuthContext,
    id: ShareId,
    access: Option<SignedAccessManifest>,
    revision: SharedRevision,
) -> AppResult<(SharedItemState, SharedItemState)> {
    require_enabled(state_)?;
    // Pre-read discovers identity lock set. Re-check the entire manifest hash
    // after acquiring the item lock; never add identity locks afterwards.
    let prior: Option<Json<SignedAccessManifest>> = sqlx::query_scalar(
        "SELECT i.current_manifest FROM shared_items i JOIN shared_item_devices d ON d.share_id=i.id
         WHERE i.id=$1 AND d.user_id=$2 AND d.device_id=$3")
        .bind(Uuid::from(id)).bind(Uuid::from(auth.user_id)).bind(Uuid::from(auth.device_id))
        .fetch_optional(&mut *conn).await?;
    let prior = prior.ok_or_else(AppError::not_found)?.0;
    if !kind_enabled(&state_.config, prior.manifest.kind) {
        return Err(if access.is_some() {
            AppError::bad_request("sharing content kind not enabled")
        } else {
            AppError::not_found()
        });
    }
    if access.is_none()
        && (revision.signed.mutation.manifest_hash.as_slice() != manifest_hash(&prior.manifest)?
            || revision.signed.mutation.manifest_revision != prior.manifest.revision
            || revision.signed.mutation.context.access_epoch != prior.manifest.access_epoch)
    {
        return Err(conflict());
    }
    let next = access.as_ref().unwrap_or(&prior);
    check_access(&state_.config, next)?;
    let hash = check_revision(&next.manifest, &revision, auth)?;
    let keys = lock_identities(&mut *conn, auth, &bindings(&next.manifest)).await?;
    for v in &next.manifest.members {
        check_member_keys(v, &keys[&Uuid::from(v.device_id)])?;
    }
    let old = store::lock_item(&mut *conn, id.into(), true).await?;
    store::role(
        &mut *conn,
        id.into(),
        auth.user_id.into(),
        auth.device_id.into(),
    )
    .await?;
    if old.manifest_hash != manifest_hash(&prior.manifest)? {
        return Err(conflict());
    }
    if old.revision >= 10000 {
        return Err(AppError::forbidden("sharing history quota reached"));
    }
    if old.deleted {
        return Err(AppError::gone("shared item deleted"));
    }
    let old_state = state(&old)?;
    let previous = &old_state.access.manifest;
    let current_member = member(previous, auth)?;
    if !current_member.role.can_write() {
        return Err(AppError::forbidden("sharing editor role required"));
    }
    check_member_keys(current_member, &keys[&Uuid::from(auth.device_id)])?;
    let m = &revision.signed.mutation;
    let deleting = m.operation == SharingOperation::Delete;
    // A recipient with edit rights must never destroy the owner's item.
    if deleting && previous.owner_user_id != auth.user_id {
        return Err(owner_only());
    }
    if m.base_revision != old.revision || m.previous_revision_hash.as_slice() != old.revision_hash {
        return Err(conflict());
    }
    if access.is_some() {
        if previous.owner_user_id != auth.user_id || previous.owner_device_id != auth.device_id {
            return Err(AppError::forbidden("sharing owner device required"));
        }
        let next = &next.manifest;
        if next.share_id != id
            || next.item_id != previous.item_id
            || next.kind != previous.kind
            || next.server_instance_id != previous.server_instance_id
            || next.owner_user_id != previous.owner_user_id
            || next.owner_device_id != previous.owner_device_id
        {
            return Err(AppError::bad_request("sharing immutable binding changed"));
        }
        if previous.revision.checked_add(1) != Some(next.revision)
            || previous.access_epoch.checked_add(1) != Some(next.access_epoch)
            || next.previous_manifest_hash.as_slice() != old.manifest_hash
        {
            return Err(conflict());
        }
        for new in &next.members {
            if let Some(old) = previous
                .members
                .iter()
                .find(|v| v.device_id == new.device_id)
            {
                if old.user_id != new.user_id
                    || old.signing_public_key != new.signing_public_key
                    || old.encryption_public_key != new.encryption_public_key
                {
                    return Err(AppError::invalid_proof("sharing pinned key changed"));
                }
            }
        }
        if revision.body.is_none() {
            return Err(AppError::bad_request(
                "access rotation requires fresh encrypted body",
            ));
        }
    } else if m.manifest_revision != old.manifest_revision as u64
        || m.context.access_epoch != old.access_epoch as u64
    {
        return Err(conflict());
    }
    check_fresh_body(&old_state.revision, &revision)?;
    persist(
        &mut *conn,
        next,
        &revision,
        hash,
        false,
        access.is_some().then_some(previous),
    )
    .await?;
    if deleting {
        // Keep the last content (ciphertext and envelopes only) restorable.
        sqlx::query(
            "UPDATE shared_items SET deleted_at=clock_timestamp(), restore_revision=$2 WHERE id=$1",
        )
        .bind(old.id)
        .bind(&old.current_mutation)
        .execute(&mut *conn)
        .await?;
    }
    super::auth::recheck_session(&mut *conn, auth).await?;
    Ok((
        old_state,
        SharedItemState {
            access: next.clone(),
            revision,
        },
    ))
}

pub(super) async fn authorized_item(
    config: &Config,
    conn: &mut PgConnection,
    auth: &AuthContext,
    id: ShareId,
    key: &super::auth::DeviceKeys,
) -> AppResult<StoredItem> {
    let row = store::lock_item(conn, id.into(), false).await?;
    store::role(conn, id.into(), auth.user_id.into(), auth.device_id.into()).await?;
    let access = state(&row)?.access.manifest;
    if !kind_enabled(config, access.kind) {
        return Err(AppError::not_found());
    }
    check_member_keys(member(&access, auth)?, key)?;
    Ok(row)
}
pub async fn get(state_: &AppState, auth: &AuthContext, id: ShareId) -> AppResult<SharedItemState> {
    require_enabled(state_)?;
    let mut tx = state_.db.begin().await?;
    let keys = lock_identities(&mut tx, auth, &[]).await?;
    let row = authorized_item(
        &state_.config,
        &mut tx,
        auth,
        id,
        &keys[&Uuid::from(auth.device_id)],
    )
    .await?;
    let result = state(&row)?;
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(result)
}
pub async fn list(
    state_: &AppState,
    auth: &AuthContext,
    after: Option<ShareId>,
    limit: u32,
) -> AppResult<ShareListPage> {
    list_with_kinds(state_, auth, after, limit, ListKinds::default()).await
}

pub async fn list_with_kinds(
    state_: &AppState,
    auth: &AuthContext,
    after: Option<ShareId>,
    limit: u32,
    kinds: ListKinds,
) -> AppResult<ShareListPage> {
    require_enabled(state_)?;
    kinds.validate(&state_.config)?;
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(AppError::bad_request("invalid sharing page limit"));
    }
    let mut tx = state_.db.begin().await?;
    let keys = lock_identities(&mut tx, auth, &[]).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT share_id FROM shared_item_devices WHERE user_id=$1 AND device_id=$2 AND share_id>$3 ORDER BY share_id LIMIT $4")
        .bind(Uuid::from(auth.user_id)).bind(Uuid::from(auth.device_id))
        .bind(Uuid::from(after.unwrap_or(ShareId::NIL))).bind(i64::from(limit)+1).fetch_all(&mut *tx).await?;
    let mut items = Vec::new();
    let mut last_scanned = None;
    let mut bytes = 0;
    let mut has_more = ids.len() > limit as usize;
    for id in ids.into_iter().take(limit as usize) {
        let row = match authorized_item(
            &state_.config,
            &mut tx,
            auth,
            id.into(),
            &keys[&Uuid::from(auth.device_id)],
        )
        .await
        {
            Ok(row) => row,
            Err(e) if e.code() == ErrorCode::NotFound => {
                last_scanned = Some(id.into());
                continue;
            }
            Err(e) => return Err(e),
        };
        let value = state(&row)?;
        if !kinds.includes(value.access.manifest.kind) {
            last_scanned = Some(id.into());
            continue;
        }
        bytes += serde_json::to_vec(&value)
            .map_err(|_| AppError::internal("sharing serialization failed"))?
            .len();
        if bytes > state_.config.sync_page_bytes && !items.is_empty() {
            has_more = true;
            break;
        }
        last_scanned = Some(id.into());
        items.push(value);
    }
    let next_after = last_scanned.filter(|_| has_more);
    let owned: Vec<Uuid> = items
        .iter()
        .filter(|v| v.access.manifest.owner_user_id == auth.user_id)
        .map(|v| v.access.manifest.share_id.into())
        .collect();
    let departures = if owned.is_empty() {
        vec![]
    } else {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT share_id, user_id FROM shared_item_departures
             WHERE share_id = ANY($1) ORDER BY share_id, user_id",
        )
        .bind(owned)
        .fetch_all(&mut *tx)
        .await?;
        rows.into_iter()
            .map(|(share_id, user_id)| ShareDeparture {
                share_id: share_id.into(),
                user_id: user_id.into(),
            })
            .collect()
    };
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(ShareListPage {
        items,
        next_after,
        has_more,
        departures,
    })
}
/// A recipient account leaves a shared item: all its devices lose server
/// access at once. The owner sees the departure in `ShareListPage` and drops
/// the account from the signed manifest with the next access change.
pub async fn leave(state_: &AppState, auth: &AuthContext, id: ShareId) -> AppResult<()> {
    require_enabled(state_)?;
    let mut tx = state_.db.begin().await?;
    let keys = lock_identities(&mut tx, auth, &[]).await?;
    let row = store::lock_item(&mut tx, id.into(), true).await?;
    store::role(
        &mut tx,
        id.into(),
        auth.user_id.into(),
        auth.device_id.into(),
    )
    .await?;
    let access = state(&row)?.access.manifest;
    if !kind_enabled(&state_.config, access.kind) {
        return Err(AppError::not_found());
    }
    check_member_keys(member(&access, auth)?, &keys[&Uuid::from(auth.device_id)])?;
    if access.owner_user_id == auth.user_id {
        return Err(AppError::forbidden(
            "the owner cannot leave a shared item; delete it instead",
        ));
    }
    sqlx::query(
        "INSERT INTO shared_item_departures (share_id,user_id) VALUES ($1,$2)
         ON CONFLICT (share_id,user_id) DO NOTHING",
    )
    .bind(row.id)
    .bind(Uuid::from(auth.user_id))
    .execute(&mut *tx)
    .await?;
    let devices = sqlx::query("DELETE FROM shared_item_devices WHERE share_id=$1 AND user_id=$2")
        .bind(row.id)
        .bind(Uuid::from(auth.user_id))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    use crate::audit::{AuditEvent, AuditType};
    AuditEvent::new(AuditType::ShareLeft)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(id)
        .meta(serde_json::json!({ "devices": devices }))
        .record(&mut *tx)
        .await?;
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(())
}

/// Owner-only listing of deleted items whose last content is retained.
pub async fn deleted(
    state_: &AppState,
    auth: &AuthContext,
    after: Option<ShareId>,
    limit: u32,
) -> AppResult<DeletedShareListPage> {
    require_enabled(state_)?;
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(AppError::bad_request("invalid sharing page limit"));
    }
    let mut tx = state_.db.begin().await?;
    let keys = lock_identities(&mut tx, auth, &[]).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM shared_items
         WHERE owner_user_id=$1 AND deleted AND restore_revision IS NOT NULL
           AND deleted_at > clock_timestamp() - make_interval(days => $2) AND id>$3
         ORDER BY id LIMIT $4",
    )
    .bind(Uuid::from(auth.user_id))
    .bind(RESTORE_WINDOW_DAYS as i32)
    .bind(Uuid::from(after.unwrap_or(ShareId::NIL)))
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut *tx)
    .await?;
    let mut items = Vec::new();
    let mut last_scanned = None;
    let mut bytes = 0;
    let mut has_more = ids.len() > limit as usize;
    for id in ids.into_iter().take(limit as usize) {
        let row = match authorized_item(
            &state_.config,
            &mut tx,
            auth,
            id.into(),
            &keys[&Uuid::from(auth.device_id)],
        )
        .await
        {
            Ok(row) => row,
            Err(e) if e.code() == ErrorCode::NotFound => {
                last_scanned = Some(id.into());
                continue;
            }
            Err(e) => return Err(e),
        };
        type Retained = (
            Option<chrono::DateTime<chrono::Utc>>,
            Option<Json<SharedRevision>>,
        );
        let (deleted_at, retained): Retained =
            sqlx::query_as("SELECT deleted_at, restore_revision FROM shared_items WHERE id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let (Some(deleted_at), Some(last_revision)) = (deleted_at, retained) else {
            last_scanned = Some(id.into());
            continue;
        };
        let departed_user_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM shared_item_departures WHERE share_id=$1 ORDER BY user_id",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        let value = DeletedSharedItem {
            state: state(&row)?,
            last_revision: last_revision.0,
            deleted_at,
            restorable_until: deleted_at + chrono::Duration::days(i64::from(RESTORE_WINDOW_DAYS)),
            departed_user_ids: departed_user_ids.into_iter().map(Into::into).collect(),
        };
        bytes += serde_json::to_vec(&value)
            .map_err(|_| AppError::internal("sharing serialization failed"))?
            .len();
        if bytes > state_.config.sync_page_bytes && !items.is_empty() {
            has_more = true;
            break;
        }
        last_scanned = Some(id.into());
        items.push(value);
    }
    let next_after = last_scanned.filter(|_| has_more);
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(DeletedShareListPage {
        items,
        next_after,
        has_more,
    })
}

pub async fn history(
    state_: &AppState,
    auth: &AuthContext,
    id: ShareId,
    after_manifest: u64,
    after_revision: i64,
    limit: u32,
) -> AppResult<ShareHistoryPage> {
    require_enabled(state_)?;
    if limit == 0 || limit > MAX_PAGE_SIZE || after_manifest > i64::MAX as u64 || after_revision < 0
    {
        return Err(AppError::bad_request("invalid sharing history cursor"));
    }
    let mut tx = state_.db.begin().await?;
    let keys = lock_identities(&mut tx, auth, &[]).await?;
    let row = authorized_item(
        &state_.config,
        &mut tx,
        auth,
        id,
        &keys[&Uuid::from(auth.device_id)],
    )
    .await?;
    if after_manifest > row.manifest_revision as u64 || after_revision > row.revision {
        return Err(conflict());
    }
    let manifests: Vec<Json<SignedAccessManifest>> = sqlx::query_scalar("SELECT document FROM shared_manifests WHERE share_id=$1 AND manifest_revision>$2 ORDER BY manifest_revision LIMIT $3")
        .bind(Uuid::from(id)).bind(after_manifest as i64).bind(i64::from(limit)).fetch_all(&mut *tx).await?;
    let revisions: Vec<Json<SignedSharingMutation>> = sqlx::query_scalar("SELECT document FROM shared_revision_headers WHERE share_id=$1 AND revision>$2 ORDER BY revision LIMIT $3")
        .bind(Uuid::from(id)).bind(after_revision).bind(i64::from(limit)).fetch_all(&mut *tx).await?;
    let has_more = after_manifest + (manifests.len() as u64) < row.manifest_revision as u64
        || after_revision + (revisions.len() as i64) < row.revision;
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(ShareHistoryPage {
        manifests: manifests.into_iter().map(|v| v.0).collect(),
        revisions: revisions.into_iter().map(|v| v.0).collect(),
        latest_manifest_revision: row.manifest_revision as u64,
        latest_revision: row.revision,
        has_more,
    })
}

pub async fn capabilities(state: &AppState, auth: &AuthContext) -> AppResult<SharingCapabilities> {
    require_enabled(state)?;
    let mut tx = state.db.begin().await?;
    lock_identities(&mut tx, auth, &[]).await?;
    let server_instance_id =
        sqlx::query_scalar("SELECT instance_id FROM sharing_instance WHERE singleton")
            .fetch_one(&mut *tx)
            .await?;
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(SharingCapabilities {
        enabled: true,
        server_instance_id,
        format: FORMAT,
        max_members: MAX_MEMBERS as u32,
        max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES as u32,
        supports_groups: state.config.shared_groups_enabled,
        supports_secrets: state.config.shared_secrets_enabled,
        supports_kube_contexts: state.config.shared_kube_contexts_enabled,
        supports_db_connections: state.config.shared_db_connections_enabled,
        supports_owner_online_enrollment_v1: state.config.sharing_owner_online_enrollment_enabled,
        supports_notes_v1: state.config.shared_notes_enabled,
    })
}

/// Exact-email discovery only. Returned keys are NOT evidence of trust.
/// Caller must verify the fingerprint out of band before signing a grant.
pub async fn recipient(
    state: &AppState,
    auth: &AuthContext,
    email: &str,
) -> AppResult<SharingRecipient> {
    require_enabled(state)?;
    state
        .rate
        .account(
            state,
            crate::config::Limit::RecipientLookupAccount,
            auth.user_id,
        )
        .await?;
    state
        .limits
        .proof_device
        .check(&Uuid::from(auth.device_id))?;
    let email = crate::util::normalize_email(email)?;
    let mut tx = state.db.begin().await?;
    lock_identities(&mut tx, auth, &[]).await?;
    let verified: bool =
        sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM users WHERE id=$1")
            .bind(Uuid::from(auth.user_id))
            .fetch_one(&mut *tx)
            .await?;
    if !verified {
        return Err(AppError::new(
            ErrorCode::EmailNotVerified,
            "verify email before sharing discovery",
        ));
    }
    let user: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE lower(email)=$1 AND status='active' AND email_verified_at IS NOT NULL")
        .bind(crate::util::email_key(&email)).fetch_optional(&mut *tx).await?;
    let user = user.ok_or_else(AppError::not_found)?;
    let rows: Vec<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT id,encryption_public_key,signing_public_key FROM devices WHERE user_id=$1 AND revoked_at IS NULL ORDER BY id LIMIT $2")
        .bind(user).bind((MAX_MEMBERS + 1) as i64).fetch_all(&mut *tx).await?;
    if rows.len() > MAX_MEMBERS {
        return Err(AppError::payload_too_large(
            "recipient has too many devices",
        ));
    }
    super::auth::recheck_session(&mut tx, auth).await?;
    tx.commit().await?;
    Ok(SharingRecipient {
        user_id: user.into(),
        devices: rows
            .into_iter()
            .map(|(device, encryption, signing)| SharingMember {
                user_id: user.into(),
                device_id: device.into(),
                encryption_public_key: encryption.into(),
                signing_public_key: signing.into(),
                role: SharingRole::Reader,
            })
            .collect(),
    })
}
