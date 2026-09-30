// SPDX-License-Identifier: AGPL-3.0-only
//! Identity locks precede all sharing item locks (same order as revocation).
use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug)]
pub(super) struct DeviceKeys {
    pub user_id: Uuid,
    pub encryption: Vec<u8>,
    pub signing: Vec<u8>,
}

/// Participants are public (user, device) bindings from the supplied manifest.
/// Callers bound their count and validate the manifest before entering here.
pub(super) async fn lock_identities(
    conn: &mut PgConnection,
    auth: &AuthContext,
    participants: &[(Uuid, Uuid)],
) -> AppResult<BTreeMap<Uuid, DeviceKeys>> {
    let mut users = BTreeSet::from([Uuid::from(auth.user_id)]);
    let mut devices = BTreeSet::from([Uuid::from(auth.device_id)]);
    for (user, device) in participants {
        users.insert(*user);
        devices.insert(*device);
    }
    let user_rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, status FROM users WHERE id = ANY($1) ORDER BY id FOR SHARE")
            .bind(users.iter().copied().collect::<Vec<_>>())
            .fetch_all(&mut *conn)
            .await?;
    if user_rows.len() != users.len() || user_rows.iter().any(|(_, s)| s != "active") {
        return Err(AppError::forbidden("sharing participant unavailable"));
    }
    type Row = (Uuid, Uuid, Vec<u8>, Vec<u8>, bool);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, user_id, encryption_public_key, signing_public_key,
                revoked_at IS NOT NULL FROM devices
         WHERE id = ANY($1) ORDER BY id FOR SHARE",
    )
    .bind(devices.iter().copied().collect::<Vec<_>>())
    .fetch_all(&mut *conn)
    .await?;
    if rows.len() != devices.len() || rows.iter().any(|r| r.4) {
        return Err(AppError::forbidden("sharing participant unavailable"));
    }
    let keys: BTreeMap<_, _> = rows
        .into_iter()
        .map(|(id, user_id, encryption, signing, _)| {
            (
                id,
                DeviceKeys {
                    user_id,
                    encryption,
                    signing,
                },
            )
        })
        .collect();
    if keys[&Uuid::from(auth.device_id)].user_id != Uuid::from(auth.user_id)
        || participants.iter().any(|(u, d)| keys[d].user_id != *u)
    {
        return Err(AppError::forbidden("sharing device binding mismatch"));
    }
    recheck_session(conn, auth).await?;
    Ok(keys)
}

/// Recheck time after any item-lock wait; identity and session locks are held.
pub(super) async fn recheck_session(conn: &mut PgConnection, auth: &AuthContext) -> AppResult<()> {
    // Lock AFTER devices/users, matching account and device revocation paths.
    // Check the exact access hash again: an AuthContext may predate rotation.
    type SessionRow = (Uuid, Uuid, Vec<u8>, DateTime<Utc>, DateTime<Utc>, bool);
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT user_id, device_id, access_token_hash, access_expires_at, expires_at,
                revoked_at IS NOT NULL FROM sessions WHERE id = $1 FOR SHARE",
    )
    .bind(Uuid::from(auth.session_id))
    .fetch_optional(&mut *conn)
    .await?;
    let (user, device, hash, access_expires, expires, revoked) =
        row.ok_or_else(AppError::unauthorized)?;
    let now = Utc::now();
    if user != Uuid::from(auth.user_id)
        || device != Uuid::from(auth.device_id)
        || hash.as_slice() != auth.access_token_hash
        || revoked
        || access_expires <= now
        || expires <= now
    {
        return Err(AppError::unauthorized());
    }
    Ok(())
}
