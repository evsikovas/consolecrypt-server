// SPDX-License-Identifier: AGPL-3.0-only
//! Notes travelling with a share (`share_notes_v1`). Ciphertext only: the
//! server checks membership, authorship, epochs and signatures, never content.
use super::{
    auth::{lock_identities, recheck_session},
    require_enabled,
    service::{authorized_item, check_member_keys, member, state},
    store::{self, StoredItem},
};
use crate::{
    auth::AuthContext,
    crypto,
    error::{AppError, AppResult},
    extract::{ApiJson, ApiPath},
    AppState,
};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use cc_protocol::{sharing::AccessManifest, sharing_notes::*, ErrorCode, ObjectId, ShareId};
use sqlx::{types::Json as DbJson, PgConnection};
use std::collections::BTreeSet;
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/shares/{id}/notes", get(list))
        .route("/v1/shares/{id}/notes/keys", put(put_keys))
        .route("/v1/shares/{id}/notes/rekey", post(rekey))
        .route(
            "/v1/shares/{id}/notes/{note}",
            put(put_note).delete(delete_note),
        )
}

fn enabled(state: &AppState) -> AppResult<()> {
    require_enabled(state)?;
    if !state.config.shared_notes_enabled {
        return Err(AppError::not_found());
    }
    Ok(())
}
fn invalid(_: cc_protocol::sharing::SharingValidationError) -> AppError {
    AppError::bad_request("invalid shared note payload")
}
fn conflict(message: &'static str) -> AppError {
    AppError::new(ErrorCode::Conflict, message)
}
fn alive(row: &StoredItem) -> AppResult<()> {
    if row.deleted {
        return Err(AppError::gone("shared item deleted"));
    }
    Ok(())
}
fn is_owner_device(m: &AccessManifest, auth: &AuthContext) -> bool {
    m.owner_user_id == auth.user_id && m.owner_device_id == auth.device_id
}
async fn instance(conn: &mut PgConnection) -> AppResult<Uuid> {
    Ok(
        sqlx::query_scalar("SELECT instance_id FROM sharing_instance WHERE singleton")
            .fetch_one(conn)
            .await?,
    )
}

/// Opens a transaction holding the caller's identity and the item lock, after
/// checking the caller is a current member with unchanged keys.
async fn member_item(
    s: &AppState,
    tx: &mut PgConnection,
    auth: &AuthContext,
    id: ShareId,
    write: bool,
) -> AppResult<(StoredItem, AccessManifest)> {
    let keys = lock_identities(&mut *tx, auth, &[]).await?;
    let row = if write {
        let row = store::lock_item(&mut *tx, id.into(), true).await?;
        store::role(
            &mut *tx,
            id.into(),
            auth.user_id.into(),
            auth.device_id.into(),
        )
        .await?;
        let access = state(&row)?.access.manifest;
        if !super::service::kind_enabled(&s.config, access.kind) {
            return Err(AppError::not_found());
        }
        check_member_keys(member(&access, auth)?, &keys[&Uuid::from(auth.device_id)])?;
        row
    } else {
        authorized_item(
            &s.config,
            &mut *tx,
            auth,
            id,
            &keys[&Uuid::from(auth.device_id)],
        )
        .await?
    };
    alive(&row)?;
    let manifest = state(&row)?.access.manifest;
    Ok((row, manifest))
}

#[derive(sqlx::FromRow)]
struct StoredNote {
    note_id: Uuid,
    author_user_id: Uuid,
    author_device_id: Uuid,
    revision: i64,
    access_epoch: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    payload_hash: Vec<u8>,
    signature: Vec<u8>,
}
impl StoredNote {
    fn wire(self) -> SharedNote {
        SharedNote {
            note_id: self.note_id.into(),
            author_user_id: self.author_user_id.into(),
            author_device_id: self.author_device_id.into(),
            revision: self.revision as u64,
            access_epoch: self.access_epoch as u64,
            nonce: self.nonce.into(),
            ciphertext: self.ciphertext.into(),
            payload_hash: self.payload_hash.into(),
            signature: self.signature.into(),
        }
    }
}

async fn list(
    State(s): State<AppState>,
    auth: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
) -> AppResult<Json<SharedNotesPage>> {
    enabled(&s)?;
    let mut tx = s.db.begin().await?;
    let (row, _) = member_item(&s, &mut tx, &auth, id, false).await?;
    let rows: Vec<StoredNote> = sqlx::query_as(
        "SELECT note_id, author_user_id, author_device_id, revision, access_epoch, nonce,
                ciphertext, payload_hash, signature
         FROM shared_notes WHERE share_id=$1 ORDER BY note_id",
    )
    .bind(row.id)
    .fetch_all(&mut *tx)
    .await?;
    let mut epochs: BTreeSet<i64> = rows.iter().map(|n| n.access_epoch).collect();
    epochs.insert(row.access_epoch);
    let key_sets: Vec<DbJson<SharedNotesKeySet>> = sqlx::query_scalar(
        "SELECT key_set FROM shared_note_keys WHERE share_id=$1 AND access_epoch = ANY($2)
         ORDER BY access_epoch",
    )
    .bind(row.id)
    .bind(epochs.into_iter().collect::<Vec<_>>())
    .fetch_all(&mut *tx)
    .await?;
    recheck_session(&mut tx, &auth).await?;
    tx.commit().await?;
    Ok(Json(SharedNotesPage {
        access_epoch: row.access_epoch as u64,
        key_sets: key_sets.into_iter().map(|k| k.0).collect(),
        notes: rows.into_iter().map(StoredNote::wire).collect(),
    }))
}

/// The owner device publishes the notes key of the current epoch once; the
/// envelopes must cover the current member devices exactly.
async fn put_keys(
    State(s): State<AppState>,
    auth: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiJson(set): ApiJson<SharedNotesKeySet>,
) -> AppResult<StatusCode> {
    enabled(&s)?;
    s.rate
        .account(&s, crate::config::Limit::ShareRevisionAccount, auth.user_id)
        .await?;
    let message = notes_key_set_message(&set).map_err(invalid)?;
    let mut tx = s.db.begin().await?;
    let (row, manifest) = member_item(&s, &mut tx, &auth, id, true).await?;
    if !is_owner_device(&manifest, &auth) {
        return Err(AppError::forbidden("sharing owner device required"));
    }
    if set.share_id != id
        || set.server_instance_id != instance(&mut tx).await?
        || set.owner_device_id != manifest.owner_device_id
    {
        return Err(AppError::bad_request(
            "shared notes key set binding mismatch",
        ));
    }
    if set.access_epoch != row.access_epoch as u64
        || set.manifest_hash.as_slice() != row.manifest_hash
    {
        return Err(conflict("sharing access changed; fetch latest state"));
    }
    let members: BTreeSet<_> = manifest.members.iter().map(|m| m.device_id).collect();
    let recipients: BTreeSet<_> = set
        .envelopes
        .iter()
        .map(|e| e.recipient_device_id)
        .collect();
    if members != recipients {
        return Err(AppError::bad_request(
            "shared notes envelopes must cover the members",
        ));
    }
    let owner = member(&manifest, &auth)?;
    if !crypto::verify_ed25519(
        owner.signing_public_key.as_slice(),
        &message,
        set.signature.as_slice(),
    ) {
        return Err(AppError::invalid_proof(
            "shared notes key set signature invalid",
        ));
    }
    let existing: Option<DbJson<SharedNotesKeySet>> = sqlx::query_scalar(
        "SELECT key_set FROM shared_note_keys WHERE share_id=$1 AND access_epoch=$2",
    )
    .bind(row.id)
    .bind(row.access_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    // A key never changes within an epoch: notes already sealed with it stay readable.
    let status = match existing {
        Some(stored) if stored.0 == set => StatusCode::OK,
        Some(_) => {
            return Err(conflict(
                "shared notes key already published for this epoch",
            ))
        }
        None => {
            sqlx::query(
                "INSERT INTO shared_note_keys (share_id, access_epoch, key_set) VALUES ($1,$2,$3)",
            )
            .bind(row.id)
            .bind(row.access_epoch)
            .bind(DbJson(&set))
            .execute(&mut *tx)
            .await?;
            StatusCode::CREATED
        }
    };
    recheck_session(&mut tx, &auth).await?;
    tx.commit().await?;
    Ok(status)
}

/// Any member writes its own notes into the current epoch; revisions advance by one.
async fn put_note(
    State(s): State<AppState>,
    auth: AuthContext,
    ApiPath((id, note_id)): ApiPath<(ShareId, ObjectId)>,
    ApiJson(note): ApiJson<SharedNote>,
) -> AppResult<Json<SharedNote>> {
    enabled(&s)?;
    s.rate
        .account(&s, crate::config::Limit::ShareRevisionAccount, auth.user_id)
        .await?;
    validate_note(&note).map_err(invalid)?;
    if note.note_id != note_id
        || note.author_user_id != auth.user_id
        || note.author_device_id != auth.device_id
    {
        return Err(AppError::bad_request(
            "shared note author must be the caller",
        ));
    }
    let mut tx = s.db.begin().await?;
    let (row, manifest) = member_item(&s, &mut tx, &auth, id, false).await?;
    if note.access_epoch != row.access_epoch as u64 {
        return Err(conflict("sharing access changed; fetch latest state"));
    }
    let keyed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM shared_note_keys WHERE share_id=$1 AND access_epoch=$2)",
    )
    .bind(row.id)
    .bind(row.access_epoch)
    .fetch_one(&mut *tx)
    .await?;
    if !keyed {
        return Err(conflict(
            "shared notes key of this epoch is not published yet",
        ));
    }
    let message = note_message(instance(&mut tx).await?, id, &note).map_err(invalid)?;
    if !crypto::verify_ed25519(
        member(&manifest, &auth)?.signing_public_key.as_slice(),
        &message,
        note.signature.as_slice(),
    ) {
        return Err(AppError::invalid_proof("shared note signature invalid"));
    }
    let existing: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT author_user_id, revision FROM shared_notes WHERE share_id=$1 AND note_id=$2 FOR UPDATE",
    )
    .bind(row.id)
    .bind(Uuid::from(note_id))
    .fetch_optional(&mut *tx)
    .await?;
    match existing {
        Some((author, _)) if author != Uuid::from(auth.user_id) => {
            return Err(AppError::forbidden(
                "shared notes are edited by their author",
            ));
        }
        Some((_, revision)) if note.revision != revision as u64 + 1 => {
            return Err(conflict("shared note changed; fetch latest state"));
        }
        None if note.revision != 1 => return Err(conflict("shared note does not exist")),
        None => {
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM shared_notes WHERE share_id=$1")
                    .bind(row.id)
                    .fetch_one(&mut *tx)
                    .await?;
            if count as usize >= MAX_NOTES_PER_SHARE {
                return Err(AppError::forbidden("shared notes quota reached"));
            }
        }
        Some(_) => {}
    }
    sqlx::query(
        "INSERT INTO shared_notes (share_id, note_id, author_user_id, author_device_id, revision,
            access_epoch, nonce, ciphertext, payload_hash, signature)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (share_id, note_id) DO UPDATE SET author_device_id=EXCLUDED.author_device_id,
            revision=EXCLUDED.revision, access_epoch=EXCLUDED.access_epoch, nonce=EXCLUDED.nonce,
            ciphertext=EXCLUDED.ciphertext, payload_hash=EXCLUDED.payload_hash,
            signature=EXCLUDED.signature, updated_at=now()",
    )
    .bind(row.id)
    .bind(Uuid::from(note_id))
    .bind(Uuid::from(note.author_user_id))
    .bind(Uuid::from(note.author_device_id))
    .bind(note.revision as i64)
    .bind(note.access_epoch as i64)
    .bind(note.nonce.as_slice())
    .bind(note.ciphertext.as_slice())
    .bind(note.payload_hash.as_slice())
    .bind(note.signature.as_slice())
    .execute(&mut *tx)
    .await?;
    recheck_session(&mut tx, &auth).await?;
    tx.commit().await?;
    Ok(Json(note))
}

/// The author, or the owner of the share, removes a note.
async fn delete_note(
    State(s): State<AppState>,
    auth: AuthContext,
    ApiPath((id, note_id)): ApiPath<(ShareId, ObjectId)>,
) -> AppResult<StatusCode> {
    enabled(&s)?;
    let mut tx = s.db.begin().await?;
    let (row, manifest) = member_item(&s, &mut tx, &auth, id, false).await?;
    let author: Option<Uuid> = sqlx::query_scalar(
        "SELECT author_user_id FROM shared_notes WHERE share_id=$1 AND note_id=$2 FOR UPDATE",
    )
    .bind(row.id)
    .bind(Uuid::from(note_id))
    .fetch_optional(&mut *tx)
    .await?;
    let author = author.ok_or_else(AppError::not_found)?;
    if author != Uuid::from(auth.user_id) && manifest.owner_user_id != auth.user_id {
        return Err(AppError::forbidden(
            "shared notes are removed by their author or the owner",
        ));
    }
    sqlx::query("DELETE FROM shared_notes WHERE share_id=$1 AND note_id=$2")
        .bind(row.id)
        .bind(Uuid::from(note_id))
        .execute(&mut *tx)
        .await?;
    recheck_session(&mut tx, &auth).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The owner device moves notes of earlier epochs into the current one.
/// Authorship, revision, payload hash and signature are kept as stored.
async fn rekey(
    State(s): State<AppState>,
    auth: AuthContext,
    ApiPath(id): ApiPath<ShareId>,
    ApiJson(req): ApiJson<RekeySharedNotesRequest>,
) -> AppResult<StatusCode> {
    enabled(&s)?;
    s.rate
        .account(&s, crate::config::Limit::ShareRevisionAccount, auth.user_id)
        .await?;
    validate_rekey(&req).map_err(invalid)?;
    let mut tx = s.db.begin().await?;
    let (row, manifest) = member_item(&s, &mut tx, &auth, id, true).await?;
    if !is_owner_device(&manifest, &auth) {
        return Err(AppError::forbidden("sharing owner device required"));
    }
    if req.access_epoch != row.access_epoch as u64 {
        return Err(conflict("sharing access changed; fetch latest state"));
    }
    let keyed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM shared_note_keys WHERE share_id=$1 AND access_epoch=$2)",
    )
    .bind(row.id)
    .bind(row.access_epoch)
    .fetch_one(&mut *tx)
    .await?;
    if !keyed {
        return Err(conflict(
            "shared notes key of this epoch is not published yet",
        ));
    }
    for note in &req.notes {
        let updated = sqlx::query(
            "UPDATE shared_notes SET access_epoch=$4, nonce=$5, ciphertext=$6, updated_at=now()
             WHERE share_id=$1 AND note_id=$2 AND revision=$3 AND access_epoch < $4",
        )
        .bind(row.id)
        .bind(Uuid::from(note.note_id))
        .bind(note.revision as i64)
        .bind(row.access_epoch)
        .bind(note.nonce.as_slice())
        .bind(note.ciphertext.as_slice())
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(conflict("shared note changed; fetch latest state"));
        }
    }
    recheck_session(&mut tx, &auth).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn routes_build() {
        let _ = super::routes();
    }
}
