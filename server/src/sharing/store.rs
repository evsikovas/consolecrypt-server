// SPDX-License-Identifier: AGPL-3.0-only
//! Storage helpers. Every state change must hold the item lock exclusively.
use crate::error::{AppError, AppResult};
use sqlx::{types::Json, PgConnection};
use uuid::Uuid;

/// Internal database representation, never an unvalidated wire response.
#[derive(sqlx::FromRow)]
pub(super) struct StoredItem {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub owner_device_id: Uuid,
    pub revision: i64,
    pub access_epoch: i64,
    pub manifest_revision: i64,
    pub manifest_hash: Vec<u8>,
    pub revision_hash: Vec<u8>,
    pub deleted: bool,
    pub current_manifest: Json<serde_json::Value>,
    pub current_mutation: Json<serde_json::Value>,
}

impl std::fmt::Debug for StoredItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredItem")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("access_epoch", &self.access_epoch)
            .finish_non_exhaustive()
    }
}

pub(super) async fn lock_item(
    conn: &mut PgConnection,
    id: Uuid,
    write: bool,
) -> AppResult<StoredItem> {
    let sql = if write {
        "SELECT * FROM shared_items WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM shared_items WHERE id=$1 FOR SHARE"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or_else(AppError::not_found)
}

pub(super) async fn role(
    conn: &mut PgConnection,
    share: Uuid,
    user: Uuid,
    device: Uuid,
) -> AppResult<String> {
    sqlx::query_scalar(
        "SELECT role FROM shared_item_devices WHERE share_id=$1 AND user_id=$2 AND device_id=$3",
    )
    .bind(share)
    .bind(user)
    .bind(device)
    .fetch_optional(conn)
    .await?
    .ok_or_else(AppError::not_found)
}

/// Called only after signatures, identity/key bindings and the old-state CAS
/// have been checked. The transaction owns the item lock until commit.
pub(super) async fn save(
    conn: &mut PgConnection,
    value: &StoredItem,
    members: &[(Uuid, Uuid, &'static str)],
    creating: bool,
    manifest_changed: bool,
) -> AppResult<()> {
    let sql = if creating {
        "INSERT INTO shared_items (id,owner_user_id,owner_device_id,revision,access_epoch,
         manifest_revision,manifest_hash,revision_hash,deleted,current_manifest,current_mutation)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO NOTHING"
    } else {
        "UPDATE shared_items SET owner_user_id=$2,owner_device_id=$3,revision=$4,
         access_epoch=$5,manifest_revision=$6,manifest_hash=$7,revision_hash=$8,
         deleted=$9,current_manifest=$10,current_mutation=$11,updated_at=clock_timestamp()
         WHERE id=$1"
    };
    let affected = sqlx::query(sql)
        .bind(value.id)
        .bind(value.owner_user_id)
        .bind(value.owner_device_id)
        .bind(value.revision)
        .bind(value.access_epoch)
        .bind(value.manifest_revision)
        .bind(&value.manifest_hash)
        .bind(&value.revision_hash)
        .bind(value.deleted)
        .bind(&value.current_manifest)
        .bind(&value.current_mutation)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if affected != 1 {
        return Err(AppError::new(
            cc_protocol::ErrorCode::Conflict,
            "sharing state changed",
        ));
    }
    if manifest_changed {
        sqlx::query("INSERT INTO shared_manifests (share_id,manifest_revision,manifest_hash,document) VALUES ($1,$2,$3,$4)")
            .bind(value.id).bind(value.manifest_revision).bind(&value.manifest_hash)
            .bind(&value.current_manifest).execute(&mut *conn).await?;
        sqlx::query("DELETE FROM shared_item_devices WHERE share_id=$1")
            .bind(value.id)
            .execute(&mut *conn)
            .await?;
        for (user, device, role) in members {
            sqlx::query("INSERT INTO shared_item_devices (share_id,user_id,device_id,role) VALUES ($1,$2,$3,$4)")
                .bind(value.id).bind(user).bind(device).bind(role).execute(&mut *conn).await?;
        }
    }
    Ok(())
}
