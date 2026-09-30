// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Real PostgreSQL contention: wait for observed row-lock waits instead of
//! assuming a spawned task has reached its authorization/CAS boundary.
mod common;

use cc_protocol::{sharing::*, ErrorCode, ShareId};
use common::{sharing::*, *};
use consolecrypt_server::{auth::AuthContext, error::AppResult, sharing::service, AppState};
use std::time::Duration;
use tokio::{task::JoinHandle, time::timeout};
use uuid::Uuid;

async fn hold_item(pool: &sqlx::PgPool, id: ShareId) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM shared_items WHERE id=$1 FOR UPDATE")
        .bind(Uuid::from(id))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

async fn wait_for_item_waiters(pool: &sqlx::PgPool, expected: i64) {
    timeout(Duration::from_secs(5), async {
        loop {
            // Each TestServer owns an isolated database, so no unrelated test
            // can satisfy this count. Never fetch query parameters or bodies.
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname=current_database() AND pid<>pg_backend_pid()
                   AND state='active' AND wait_event_type='Lock'
                   AND query LIKE '%FROM shared_items WHERE id=%'",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sharing operations did not reach the held item lock");
}

fn spawn_put(
    state: &AppState,
    auth: AuthContext,
    id: ShareId,
    revision: SharedRevision,
) -> JoinHandle<AppResult<SharedItemState>> {
    let state = state.clone();
    tokio::spawn(async move {
        service::put(&state, &auth, id, PutSharedRevisionRequest { revision }).await
    })
}

async fn completed<T>(task: JoinHandle<AppResult<T>>) -> AppResult<T> {
    timeout(Duration::from_secs(10), task)
        .await
        .expect("sharing operation did not finish after releasing the lock")
        .expect("sharing task panicked")
}

async fn history_counts(pool: &sqlx::PgPool, id: ShareId) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM shared_revision_headers WHERE share_id=$1),
                (SELECT count(*) FROM shared_manifests WHERE share_id=$1)",
    )
    .bind(Uuid::from(id))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn concurrent_edits_have_exactly_one_cas_winner() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(&srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = old.access.manifest.share_id;
    let owner_edit = revision(&owner, &old.access.manifest, Some(&old.revision));
    let editor_edit = revision(&editor, &old.access.manifest, Some(&old.revision));
    let held = hold_item(&srv.state.db, id).await;
    let first = spawn_put(&srv.state, context(&owner), id, owner_edit);
    let second = spawn_put(&srv.state, context(&editor), id, editor_edit);
    wait_for_item_waiters(&srv.state.db, 2).await;
    held.commit().await.unwrap();

    let results = [completed(first).await, completed(second).await];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let winner = results.iter().find_map(|r| r.as_ref().ok()).unwrap();
    let loser = results.iter().find_map(|r| r.as_ref().err()).unwrap();
    assert_eq!(loser.code(), ErrorCode::Conflict);
    let actual = service::get(&srv.state, &context(&owner), id)
        .await
        .unwrap();
    assert!(
        actual == *winner,
        "stored state must match the winning signed edit"
    );
    assert_eq!(actual.revision.signed.mutation.context.revision, 2);
    assert_eq!(actual.access.manifest.access_epoch, 1);
    assert_eq!(history_counts(&srv.state.db, id).await, (2, 1));
}

async fn edit_access_change_race(srv: &TestServer, downgrade: bool) {
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = old.access.manifest.share_id;
    let mut members = vec![member(&owner, SharingRole::Editor)];
    if downgrade {
        members.push(member(&editor, SharingRole::Reader));
    }
    let rotate_request = rotation(&owner, &old, members.clone());
    let edit_request = revision(&editor, &old.access.manifest, Some(&old.revision));
    let held = hold_item(&srv.state.db, id).await;
    let edit = spawn_put(&srv.state, context(&editor), id, edit_request);
    let state = srv.state.clone();
    let owner_auth = context(&owner);
    let rotate =
        tokio::spawn(async move { service::rotate(&state, &owner_auth, id, rotate_request).await });
    wait_for_item_waiters(&srv.state.db, 2).await;
    held.commit().await.unwrap();

    let edit = completed(edit).await;
    let rotate = completed(rotate).await;
    assert_ne!(
        edit.is_ok(),
        rotate.is_ok(),
        "exactly one CAS transition must win"
    );
    if let Err(error) = &edit {
        assert!(matches!(
            error.code(),
            ErrorCode::Conflict | ErrorCode::NotFound
        ));
    }
    if let Err(error) = &rotate {
        assert_eq!(error.code(), ErrorCode::Conflict);
    }
    let actual = service::get(&srv.state, &context(&owner), id)
        .await
        .unwrap();
    assert_eq!(actual.revision.signed.mutation.context.revision, 2);
    let expected_manifests = if rotate.is_ok() { 2 } else { 1 };
    assert_eq!(
        history_counts(&srv.state.db, id).await,
        (2, expected_manifests)
    );
    let winner = rotate.as_ref().ok().or_else(|| edit.as_ref().ok()).unwrap();
    assert!(
        actual == *winner,
        "losing transition must leave no partial state"
    );

    // If the edit won, the owner can retry against that exact new revision.
    // Both scheduling orders must finish with the intended access removal.
    let final_state = if rotate.is_ok() {
        actual
    } else {
        service::rotate(
            &srv.state,
            &context(&owner),
            id,
            rotation(&owner, &actual, members),
        )
        .await
        .unwrap()
    };
    assert_eq!(final_state.access.manifest.access_epoch, 2);
    let read = service::get(&srv.state, &context(&editor), id).await;
    if downgrade {
        assert!(read.is_ok());
        let denied = service::put(
            &srv.state,
            &context(&editor),
            id,
            PutSharedRevisionRequest {
                revision: revision(
                    &editor,
                    &final_state.access.manifest,
                    Some(&final_state.revision),
                ),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(denied.code(), ErrorCode::Forbidden);
    } else {
        assert_eq!(read.unwrap_err().code(), ErrorCode::NotFound);
        assert!(!final_state
            .revision
            .body
            .as_ref()
            .unwrap()
            .envelopes
            .iter()
            .any(|e| e.recipient_device_id == editor.device.id));
    }
}

#[tokio::test]
async fn edit_racing_with_revoke_has_one_atomic_winner() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    edit_access_change_race(&srv, false).await;
}

#[tokio::test]
async fn edit_racing_with_downgrade_has_one_atomic_winner() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    edit_access_change_race(&srv, true).await;
}

#[tokio::test]
async fn list_cursor_advances_when_first_candidate_loses_access() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let first = create(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let second = create(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let mut ids = [
        first.access.manifest.share_id,
        second.access.manifest.share_id,
    ];
    ids.sort();
    let mut held = hold_item(&srv.state.db, ids[0]).await;
    let state = srv.state.clone();
    let auth = context(&reader);
    let list = tokio::spawn(async move { service::list(&state, &auth, None, 1).await });
    wait_for_item_waiters(&srv.state.db, 1).await;

    // Model the ACL part of an access change under the same item lock. The
    // list already discovered both candidates but must recheck current ACL.
    sqlx::query("DELETE FROM shared_item_devices WHERE share_id=$1 AND device_id=$2")
        .bind(Uuid::from(ids[0]))
        .bind(Uuid::from(reader.device.id))
        .execute(&mut *held)
        .await
        .unwrap();
    held.commit().await.unwrap();
    let page = completed(list).await.unwrap();
    assert!(page.items.is_empty());
    assert!(page.has_more);
    assert_eq!(page.next_after, Some(ids[0]));
    let next = service::list(&srv.state, &context(&reader), page.next_after, 1)
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1);
    assert_eq!(next.items[0].access.manifest.share_id, ids[1]);
    assert!(!next.has_more);
    assert_eq!(next.next_after, None);
}

#[tokio::test]
async fn expiry_while_waiting_denies_read_and_rolls_back_write() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let old = create(&srv, &owner, &[]).await;
    let id = old.access.manifest.share_id;
    let held = hold_item(&srv.state.db, id).await;
    let deadline: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "UPDATE sessions SET access_expires_at=clock_timestamp()+interval '5 seconds'
         WHERE id=$1 RETURNING access_expires_at",
    )
    .bind(Uuid::from(owner.session_id))
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    let state = srv.state.clone();
    let auth = context(&owner);
    let read = tokio::spawn(async move { service::get(&state, &auth, id).await });
    let write = spawn_put(
        &srv.state,
        context(&owner),
        id,
        revision(&owner, &old.access.manifest, Some(&old.revision)),
    );
    wait_for_item_waiters(&srv.state.db, 2).await;
    // Neither task can complete until release. Use the actual stored deadline
    // so this checks expiry after a lock wait, not a stale initial session.
    let remaining = (deadline - chrono::Utc::now()).to_std().unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(50)).await;
    held.commit().await.unwrap();
    for result in [completed(read).await, completed(write).await] {
        assert_eq!(result.unwrap_err().code(), ErrorCode::Unauthorized);
    }
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT current_mutation FROM shared_items WHERE id=$1")
            .bind(Uuid::from(id))
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert!(
        stored == serde_json::to_value(&old.revision).unwrap(),
        "expired write must roll back ciphertext and revision"
    );
    assert_eq!(history_counts(&srv.state.db, id).await, (1, 1));
}
