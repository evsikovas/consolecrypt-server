// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment documents are modified only while holding the shared item lock.
use crate::error::{AppError, AppResult};
use cc_protocol::sharing_enrollment::*;
use cc_protocol::ErrorCode;
use sqlx::{types::Json, PgConnection};
use uuid::Uuid;

pub(super) fn conflict() -> AppError {
    AppError::new(ErrorCode::Conflict, "enrollment state changed")
}
pub(super) async fn grant(
    conn: &mut PgConnection,
    share: Uuid,
    id: Uuid,
) -> AppResult<SignedSharingOwnDevicesGrantState> {
    let value: Option<Json<SignedSharingOwnDevicesGrantState>> = sqlx::query_scalar(
        "SELECT document FROM shared_enrollment_grants WHERE share_id=$1 AND grant_id=$2",
    )
    .bind(share)
    .bind(id)
    .fetch_optional(conn)
    .await?;
    value.map(|v| v.0).ok_or_else(AppError::not_found)
}
pub(super) async fn save_grant(
    conn: &mut PgConnection,
    signed: &SignedSharingOwnDevicesGrantState,
    hash: &[u8],
    creating: bool,
) -> AppResult<()> {
    let g = &signed.grant;
    let status = if g.status == EnrollmentGrantStatus::Active {
        "active"
    } else {
        "revoked"
    };
    let sql = if creating {
        "INSERT INTO shared_enrollment_grants (share_id,grant_id,revision,state_hash,
         access_manifest_hash,not_before,anchor_user_id,anchor_device_id,status,expires_at,document)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING"
    } else {
        "UPDATE shared_enrollment_grants SET revision=$3,state_hash=$4,
         access_manifest_hash=$5,not_before=$6,anchor_user_id=$7,anchor_device_id=$8,
         status=$9,expires_at=$10,document=$11 WHERE share_id=$1 AND grant_id=$2"
    };
    let count = sqlx::query(sql)
        .bind(Uuid::from(g.scope.share_id))
        .bind(g.grant_id)
        .bind(g.grant_revision as i64)
        .bind(hash)
        .bind(g.access_manifest_hash.as_slice())
        .bind(g.not_before)
        .bind(Uuid::from(g.anchor.user_id))
        .bind(Uuid::from(g.anchor.device_id))
        .bind(status)
        .bind(g.expires_at)
        .bind(Json(signed))
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if count != 1 {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO shared_enrollment_grant_states (share_id,grant_id,revision,state_hash,document)
        VALUES ($1,$2,$3,$4,$5)")
        .bind(Uuid::from(g.scope.share_id)).bind(g.grant_id).bind(g.grant_revision as i64)
        .bind(hash).bind(Json(signed)).execute(conn).await?;
    Ok(())
}
pub(super) async fn request(
    conn: &mut PgConnection,
    share: Uuid,
    id: Uuid,
) -> AppResult<OwnDeviceRequestState> {
    let value: Option<Json<OwnDeviceRequestState>> = sqlx::query_scalar(
        "SELECT document FROM shared_enrollment_requests WHERE share_id=$1 AND request_id=$2",
    )
    .bind(share)
    .bind(id)
    .fetch_optional(conn)
    .await?;
    value.map(|v| v.0).ok_or_else(AppError::not_found)
}
pub(super) async fn insert_request(
    conn: &mut PgConnection,
    state: &OwnDeviceRequestState,
    hash: &[u8],
) -> AppResult<()> {
    let r = &state.request.request;
    let count = sqlx::query(
        "INSERT INTO shared_enrollment_requests (share_id,request_id,grant_id,
        grant_state_hash,request_hash,nonce,target_user_id,target_device_id,expires_at,document)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from(r.scope.share_id))
    .bind(r.request_id)
    .bind(state.grant_id)
    .bind(r.grant_state_hash.as_slice())
    .bind(hash)
    .bind(r.nonce.as_slice())
    .bind(Uuid::from(r.target.user_id))
    .bind(Uuid::from(r.target.device_id))
    .bind(r.expires_at)
    .bind(Json(state))
    .execute(conn)
    .await?
    .rows_affected();
    if count != 1 {
        return Err(conflict());
    }
    Ok(())
}
pub(super) async fn save_request(
    conn: &mut PgConnection,
    state: &OwnDeviceRequestState,
) -> AppResult<()> {
    let r = &state.request.request;
    let count = sqlx::query(
        "UPDATE shared_enrollment_requests SET document=$3,accepted=$4
        WHERE share_id=$1 AND request_id=$2 AND NOT accepted",
    )
    .bind(Uuid::from(r.scope.share_id))
    .bind(r.request_id)
    .bind(Json(state))
    .bind(state.status == OwnDeviceRequestStatus::Accepted)
    .execute(conn)
    .await?
    .rows_affected();
    if count != 1 {
        return Err(conflict());
    }
    Ok(())
}
pub(super) async fn remember_challenge(
    conn: &mut PgConnection,
    share: Uuid,
    request: Uuid,
    signed: &SignedSharingDeviceChallenge,
) -> AppResult<()> {
    let c = &signed.challenge;
    let count = sqlx::query(
        "INSERT INTO shared_enrollment_challenges (share_id,request_id,generation,
        challenge_id,ephemeral_public_key,nonce,ciphertext_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT DO NOTHING",
    )
    .bind(share)
    .bind(request)
    .bind(c.generation as i64)
    .bind(c.challenge_id)
    .bind(c.ephemeral_public_key.as_slice())
    .bind(c.nonce.as_slice())
    .bind(crate::crypto::sha256(c.ciphertext.as_slice()).as_slice())
    .execute(conn)
    .await?
    .rows_affected();
    if count != 1 {
        return Err(conflict());
    }
    Ok(())
}
