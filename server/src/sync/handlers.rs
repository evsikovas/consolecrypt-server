// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `POST /v1/sync/push`, `GET /v1/sync/changes`, `GET /v1/sync/snapshot`.

use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::extract::{ApiJson, ApiQuery, ClientIp};
use crate::state::AppState;
use crate::vaults::VaultAccess;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use cc_protocol::events::ServerEvent;
use cc_protocol::limits;
use cc_protocol::sync::{
    Change, ChangesQuery, ChangesResponse, EncryptedBody, Mutation, MutationOp, MutationResult,
    PushRequest, PushResponse, SnapshotQuery, SnapshotResponse, OBJECT_FORMAT_V1,
};
use cc_protocol::{DeviceId, VaultId};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Structural validation of a whole batch before anything is applied.
pub fn validate_push(req: &PushRequest) -> AppResult<()> {
    if req.mutations.len() > limits::MAX_PUSH_BATCH {
        return Err(AppError::payload_too_large(
            "too many mutations in one push (max 500)",
        ));
    }
    let mut objects = HashSet::with_capacity(req.mutations.len());
    let mut mutations = HashSet::with_capacity(req.mutations.len());
    for m in &req.mutations {
        if !objects.insert(m.object_id) {
            return Err(AppError::bad_request("duplicate object_id in one push"));
        }
        if !mutations.insert(m.mutation_id) {
            return Err(AppError::bad_request("duplicate mutation_id in one push"));
        }
        if m.object_id.as_uuid().is_nil() || m.mutation_id.as_uuid().is_nil() {
            return Err(AppError::bad_request("nil object_id or mutation_id"));
        }
        if m.base_revision < 0 {
            return Err(AppError::bad_request("base_revision must be >= 0"));
        }
        if let MutationOp::Put { body } = &m.op {
            validate_body(body)?;
        }
    }
    Ok(())
}

fn validate_body(body: &EncryptedBody) -> AppResult<()> {
    if body.format != OBJECT_FORMAT_V1 {
        return Err(AppError::bad_request("unsupported object format"));
    }
    if body.ciphertext.len() > limits::MAX_OBJECT_CIPHERTEXT_BYTES {
        return Err(AppError::payload_too_large(
            "object ciphertext exceeds 1 MiB",
        ));
    }
    if body.ciphertext.len() < limits::TAG_LEN
        || body.nonce.len() != limits::NONCE_LEN
        || body.wrapped_dek.len() != limits::WRAPPED_DEK_LEN
        || body.wrapped_dek_nonce.len() != limits::NONCE_LEN
    {
        return Err(AppError::bad_request("malformed encrypted body"));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct StoredMutation {
    mutation_id: Uuid,
    vault_id: Uuid,
    object_id: Uuid,
    result_revision: i64,
    result_sequence: i64,
}

#[derive(sqlx::FromRow)]
struct CurrentObject {
    object_id: Uuid,
    revision: i64,
    sequence: i64,
    deleted: bool,
    size: i64,
}

/// `POST /v1/sync/push` → `200`/`409` `PushResponse` (ADR-0003 §Push).
pub async fn push(
    State(state): State<AppState>,
    auth: AuthContext,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<PushRequest>,
) -> AppResult<(StatusCode, Json<PushResponse>)> {
    if req.device_id != auth.device_id {
        return Err(AppError::forbidden(
            "device_id does not match the authenticated device",
        ));
    }
    validate_push(&req)?;
    let vault_id = req.vault_id;
    VaultAccess::load(&state.db, &auth, vault_id)
        .await?
        .require_trusted()?;

    let db_timer = crate::db::DbTimer::start("sync_push");
    let mut tx = state.db.begin().await?;
    // Serialise pushes per vault; everything below sees a stable vault.
    let locked: Option<(i64, i64)> = sqlx::query_as(
        "SELECT s.last_sequence, s.stored_bytes FROM vault_sequences s
           JOIN vaults v ON v.id = s.vault_id AND v.state = 'active'
          WHERE s.vault_id = $1
          FOR UPDATE OF s",
    )
    .bind(Uuid::from(vault_id))
    .fetch_optional(&mut *tx)
    .await?;
    let (last_sequence, stored_bytes) =
        locked.ok_or_else(|| AppError::gone("vault was deleted"))?;
    // Re-check trust under the lock (a concurrent revocation wins).
    let still_trusted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM vault_key_envelopes
                         WHERE vault_id = $1 AND recipient_type = 'device'
                           AND recipient_id = $2 AND revoked_at IS NULL)",
    )
    .bind(Uuid::from(vault_id))
    .bind(Uuid::from(auth.device_id))
    .fetch_one(&mut *tx)
    .await?;
    if !still_trusted {
        return Err(AppError::device_not_trusted());
    }

    let mutation_ids: Vec<Uuid> = req.mutations.iter().map(|m| m.mutation_id.into()).collect();
    let stored: Vec<StoredMutation> = sqlx::query_as(
        "SELECT mutation_id, vault_id, object_id, result_revision, result_sequence
           FROM sync_mutations WHERE mutation_id = ANY($1)",
    )
    .bind(&mutation_ids)
    .fetch_all(&mut *tx)
    .await?;
    let mut replayed: HashMap<Uuid, StoredMutation> = HashMap::with_capacity(stored.len());
    for s in stored {
        replayed.insert(s.mutation_id, s);
    }
    for m in &req.mutations {
        if let Some(s) = replayed.get(&Uuid::from(m.mutation_id)) {
            if s.vault_id != Uuid::from(vault_id) || s.object_id != Uuid::from(m.object_id) {
                return Err(AppError::bad_request(
                    "mutation_id was already used for a different object",
                ));
            }
        }
    }

    let object_ids: Vec<Uuid> = req
        .mutations
        .iter()
        .filter(|m| !replayed.contains_key(&Uuid::from(m.mutation_id)))
        .map(|m| m.object_id.into())
        .collect();
    let current: Vec<CurrentObject> = sqlx::query_as(
        "SELECT object_id, revision, sequence, deleted,
                COALESCE(octet_length(ciphertext), 0)::bigint AS size
           FROM vault_objects
          WHERE vault_id = $1 AND object_id = ANY($2)",
    )
    .bind(Uuid::from(vault_id))
    .bind(&object_ids)
    .fetch_all(&mut *tx)
    .await?;
    let current: HashMap<Uuid, CurrentObject> =
        current.into_iter().map(|c| (c.object_id, c)).collect();

    let mut sequence = last_sequence;
    let mut stored = stored_bytes;
    let mut results = Vec::with_capacity(req.mutations.len());
    let (mut accepted, mut conflicts, mut replays) = (0u32, 0u32, 0u32);
    for m in &req.mutations {
        if let Some(s) = replayed.get(&Uuid::from(m.mutation_id)) {
            replays += 1;
            results.push(MutationResult::Accepted {
                mutation_id: m.mutation_id,
                object_id: m.object_id,
                revision: s.result_revision,
                sequence: s.result_sequence,
                replayed: true,
            });
            continue;
        }
        let cur = current.get(&Uuid::from(m.object_id));
        let current_revision = cur.map_or(0, |c| c.revision);
        if m.base_revision != current_revision {
            conflicts += 1;
            results.push(MutationResult::Conflict {
                mutation_id: m.mutation_id,
                object_id: m.object_id,
                current_revision,
                current_sequence: cur.map_or(0, |c| c.sequence),
                current_deleted: cur.is_some_and(|c| c.deleted),
            });
            continue;
        }
        let new_size = match &m.op {
            MutationOp::Put { body } => body.ciphertext.len() as i64,
            MutationOp::Delete => 0,
        };
        stored += new_size - cur.map_or(0, |c| c.size);
        if stored > state.config.max_vault_bytes && new_size > 0 {
            // Whole request rejected; nothing of it is committed.
            return Err(
                AppError::payload_too_large("vault storage quota exceeded").with_details(
                    serde_json::json!({
                        "reason": "vault_quota",
                        "limit_bytes": state.config.max_vault_bytes,
                    }),
                ),
            );
        }
        sequence += 1;
        let revision = m.base_revision + 1;
        apply(&mut tx, vault_id, auth.device_id, m, revision, sequence).await?;
        accepted += 1;
        results.push(MutationResult::Accepted {
            mutation_id: m.mutation_id,
            object_id: m.object_id,
            revision,
            sequence,
            replayed: false,
        });
    }

    if sequence != last_sequence {
        sqlx::query(
            "UPDATE vault_sequences SET last_sequence = $2, stored_bytes = $3 WHERE vault_id = $1",
        )
        .bind(Uuid::from(vault_id))
        .bind(sequence)
        .bind(stored.max(0))
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE vaults SET updated_at = now() WHERE id = $1")
            .bind(Uuid::from(vault_id))
            .execute(&mut *tx)
            .await?;
    }
    if accepted > 0 || conflicts > 0 {
        AuditEvent::new(AuditType::SyncPush)
            .user(auth.user_id)
            .device(auth.device_id)
            .target(vault_id)
            .ip(ip)
            .meta(serde_json::json!({
                "accepted": accepted,
                "conflicts": conflicts,
                "replayed": replays,
                "sequence": sequence,
            }))
            .record(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    drop(db_timer);

    metrics::counter!("cc_sync_push_mutations_total", "result" => "accepted")
        .increment(accepted.into());
    metrics::counter!("cc_sync_push_mutations_total", "result" => "replayed")
        .increment(replays.into());
    metrics::counter!("cc_sync_conflicts_total").increment(conflicts.into());
    if sequence != last_sequence {
        state
            .events
            .publish_vault(
                &state.db,
                vault_id,
                ServerEvent::VaultChanged {
                    vault_id,
                    latest_sequence: sequence,
                },
            )
            .await;
    }
    let status = if conflicts > 0 {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(PushResponse {
            results,
            latest_sequence: sequence,
        }),
    ))
}

async fn apply(
    conn: &mut sqlx::PgConnection,
    vault_id: VaultId,
    device_id: DeviceId,
    m: &Mutation,
    revision: i64,
    sequence: i64,
) -> AppResult<()> {
    let (deleted, body) = match &m.op {
        MutationOp::Put { body } => (false, Some(body)),
        MutationOp::Delete => (true, None),
    };
    sqlx::query(
        "INSERT INTO vault_objects
             (vault_id, object_id, revision, sequence, deleted, format, ciphertext, nonce,
              wrapped_dek, wrapped_dek_nonce, writer_device_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (vault_id, object_id) DO UPDATE
            SET revision = EXCLUDED.revision, sequence = EXCLUDED.sequence,
                deleted = EXCLUDED.deleted, format = EXCLUDED.format,
                ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce,
                wrapped_dek = EXCLUDED.wrapped_dek, wrapped_dek_nonce = EXCLUDED.wrapped_dek_nonce,
                writer_device_id = EXCLUDED.writer_device_id, updated_at = now()",
    )
    .bind(Uuid::from(vault_id))
    .bind(Uuid::from(m.object_id))
    .bind(revision)
    .bind(sequence)
    .bind(deleted)
    .bind(body.map(|b| b.format as i16))
    .bind(body.map(|b| b.ciphertext.as_slice()))
    .bind(body.map(|b| b.nonce.as_slice()))
    .bind(body.map(|b| b.wrapped_dek.as_slice()))
    .bind(body.map(|b| b.wrapped_dek_nonce.as_slice()))
    .bind(Uuid::from(device_id))
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO sync_mutations
             (mutation_id, vault_id, object_id, device_id, result_revision, result_sequence)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::from(m.mutation_id))
    .bind(Uuid::from(vault_id))
    .bind(Uuid::from(m.object_id))
    .bind(Uuid::from(device_id))
    .bind(revision)
    .bind(sequence)
    .execute(conn)
    .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct ObjectRow {
    object_id: Uuid,
    revision: i64,
    sequence: i64,
    deleted: bool,
    format: Option<i16>,
    ciphertext: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    wrapped_dek: Option<Vec<u8>>,
    wrapped_dek_nonce: Option<Vec<u8>>,
    writer_device_id: Uuid,
    updated_at: DateTime<Utc>,
}

/// Per-item overhead counted against the page byte budget (ids, nonces,
/// wrapped DEK, JSON framing).
const ROW_OVERHEAD_BYTES: i64 = 256;

impl ObjectRow {
    fn into_change(self) -> AppResult<Change> {
        let body = if self.deleted {
            None
        } else {
            match (
                self.format,
                self.ciphertext,
                self.nonce,
                self.wrapped_dek,
                self.wrapped_dek_nonce,
            ) {
                (Some(format), Some(ciphertext), Some(nonce), Some(wrapped_dek), Some(wn)) => {
                    Some(EncryptedBody {
                        format: u16::try_from(format)
                            .map_err(|_| AppError::internal("invalid stored object format"))?,
                        ciphertext: ciphertext.into(),
                        nonce: nonce.into(),
                        wrapped_dek: wrapped_dek.into(),
                        wrapped_dek_nonce: wn.into(),
                    })
                }
                _ => return Err(AppError::internal("live object without body")),
            }
        };
        Ok(Change {
            object_id: self.object_id.into(),
            revision: self.revision,
            sequence: self.sequence,
            deleted: self.deleted,
            body,
            writer_device_id: self.writer_device_id.into(),
            updated_at: self.updated_at,
        })
    }
}

fn page_limit(limit: Option<u32>) -> i64 {
    i64::from(
        limit
            .unwrap_or(limits::DEFAULT_PAGE_LIMIT)
            .clamp(1, limits::MAX_PAGE_LIMIT),
    )
}

/// One page plus the vault's latest sequence, read from the SAME database
/// snapshot (REPEATABLE READ, read-only): clients continue with
/// `changes?after=<latest_sequence of the first snapshot page>`, so the two
/// must be consistent or tombstones created while paging could be missed.
///
/// Rows are streamed in sequence order and the page stops at `limit` items or
/// when the byte budget is used up (at least one item is always returned).
async fn fetch_page(
    state: &AppState,
    vault_id: VaultId,
    after: i64,
    limit: i64,
    live_only: bool,
) -> AppResult<Page> {
    let _db_timer = crate::db::DbTimer::start("sync_page");
    let mut tx = state.db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let (latest_sequence, epoch): (i64, Uuid) = sqlx::query_as(
        "SELECT s.last_sequence, v.epoch FROM vault_sequences s
           JOIN vaults v ON v.id = s.vault_id
          WHERE s.vault_id = $1",
    )
    .bind(Uuid::from(vault_id))
    .fetch_one(&mut *tx)
    .await?;

    // Choose the page boundary from sizes only (octet_length reads the TOAST
    // header, not the value), then fetch just the bodies inside it: the DB
    // never streams more than one page of ciphertext.
    let sizes: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT sequence, COALESCE(octet_length(ciphertext), 0)::bigint
           FROM vault_objects
          WHERE vault_id = $1 AND sequence > $2 AND (NOT $3 OR NOT deleted)
          ORDER BY sequence
          LIMIT $4",
    )
    .bind(Uuid::from(vault_id))
    .bind(after)
    .bind(live_only)
    .bind(limit + 1)
    .fetch_all(&mut *tx)
    .await?;
    let budget = state.config.sync_page_bytes as i64;
    let mut used = 0i64;
    let mut take = 0usize;
    for (_, size) in &sizes {
        let cost = size + ROW_OVERHEAD_BYTES;
        if take as i64 == limit || (take > 0 && used + cost > budget) {
            break;
        }
        used += cost;
        take += 1;
    }
    let has_more = sizes.len() > take;
    let items = match sizes.get(take.wrapping_sub(1)) {
        Some((cutoff, _)) if take > 0 => sqlx::query_as::<_, ObjectRow>(
            "SELECT object_id, revision, sequence, deleted, format, ciphertext, nonce,
                    wrapped_dek, wrapped_dek_nonce, writer_device_id, updated_at
               FROM vault_objects
              WHERE vault_id = $1 AND sequence > $2 AND sequence <= $3
                AND (NOT $4 OR NOT deleted)
              ORDER BY sequence",
        )
        .bind(Uuid::from(vault_id))
        .bind(after)
        .bind(*cutoff)
        .bind(live_only)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(ObjectRow::into_change)
        .collect::<AppResult<Vec<_>>>()?,
        _ => Vec::new(),
    };
    tx.rollback().await?;
    Ok(Page {
        items,
        has_more,
        latest_sequence,
        epoch,
    })
}

struct Page {
    items: Vec<Change>,
    has_more: bool,
    latest_sequence: i64,
    epoch: Uuid,
}

/// `GET /v1/sync/changes?vault_id&after&limit` → `ChangesResponse` (T(V)).
pub async fn changes(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiQuery(q): ApiQuery<ChangesQuery>,
) -> AppResult<Json<ChangesResponse>> {
    if q.after < 0 {
        return Err(AppError::bad_request("after must be >= 0"));
    }
    VaultAccess::load(&state.db, &auth, q.vault_id)
        .await?
        .require_trusted()?;
    // Tombstones are never compacted (ADR-0202), so there is no horizon and
    // `410 gone` is not produced here in v1.
    let page = fetch_page(&state, q.vault_id, q.after, page_limit(q.limit), false).await?;
    metrics::counter!("cc_sync_pull_requests_total", "kind" => "changes").increment(1);
    Ok(Json(ChangesResponse {
        next_after: page.items.last().map_or(q.after, |c| c.sequence),
        changes: page.items,
        has_more: page.has_more,
        latest_sequence: page.latest_sequence,
        epoch: Some(page.epoch),
    }))
}

/// `GET /v1/sync/snapshot?vault_id&cursor&limit` → `SnapshotResponse` (T(V)).
pub async fn snapshot(
    State(state): State<AppState>,
    auth: AuthContext,
    ApiQuery(q): ApiQuery<SnapshotQuery>,
) -> AppResult<Json<SnapshotResponse>> {
    let cursor = q.cursor.unwrap_or(0);
    if cursor < 0 {
        return Err(AppError::bad_request("cursor must be >= 0"));
    }
    VaultAccess::load(&state.db, &auth, q.vault_id)
        .await?
        .require_trusted()?;
    let page = fetch_page(&state, q.vault_id, cursor, page_limit(q.limit), true).await?;
    metrics::counter!("cc_sync_pull_requests_total", "kind" => "snapshot").increment(1);
    Ok(Json(SnapshotResponse {
        next_cursor: if page.has_more {
            page.items.last().map(|o| o.sequence)
        } else {
            None
        },
        objects: page.items,
        latest_sequence: page.latest_sequence,
        epoch: Some(page.epoch),
    }))
}
