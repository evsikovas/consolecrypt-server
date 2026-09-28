// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Retention / maintenance pass.

mod common;

use cc_protocol::{paths, ObjectId};
use common::*;
use consolecrypt_server::jobs;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn maintenance_purges_only_what_is_old() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let doomed = srv.create_vault(&a).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    srv.push(&a, doomed.id, vec![put(ObjectId::new(), 0)]).await;
    let b = srv.new_device_session(&a, "B").await;
    srv.post(paths::DEVICES, Some(&b.access), &json!({})).await;
    let (s, _) = srv
        .delete(
            &paths::fill(paths::VAULT, &[("vault_id", &doomed.id.to_string())]),
            &a.access,
            Some(&json!({"vault_access_key": doomed.vak_bytes()})),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    srv.request::<()>(
        reqwest::Method::POST,
        paths::AUTH_LOGOUT,
        Some(&b.access),
        None,
    )
    .await;

    // Nothing is old yet: a pass changes nothing that matters.
    let r = jobs::run_once(&srv.state).await.unwrap();
    assert!(!r.skipped_locked);
    assert_eq!(r.vaults_purged, 0);
    assert_eq!(r.sync_mutations_deleted, 0);
    assert_eq!(r.sessions_deleted, 0);

    // Age everything artificially.
    for sql in [
        "UPDATE vaults SET deleted_at = now() - interval '31 days' WHERE state = 'deleted'",
        "UPDATE sync_mutations SET accepted_at = now() - interval '31 days'",
        "UPDATE sessions SET revoked_at = now() - interval '8 days' WHERE revoked_at IS NOT NULL",
        "UPDATE device_requests SET expires_at = now() - interval '1 hour'",
        "UPDATE audit_events SET occurred_at = now() - interval '400 days'",
    ] {
        sqlx::query(sql).execute(&srv.state.db).await.unwrap();
    }
    let r = jobs::run_once(&srv.state).await.unwrap();
    assert_eq!(r.vaults_purged, 1);
    assert_eq!(r.sync_mutations_deleted, 2);
    assert_eq!(r.sessions_deleted, 1);
    assert_eq!(r.requests_expired, 1);
    assert!(r.audit_events_deleted > 0);

    // The live vault and its data are untouched and still sync.
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM vaults").await, 1);
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        1
    );
    assert_eq!(srv.changes(&a, vault.id, 0).await.0, StatusCode::OK);
    assert_eq!(srv.get(paths::AUTH_ME, &a.access).await.0, StatusCode::OK);
}

#[tokio::test]
async fn only_one_replica_runs_maintenance_at_a_time() {
    let srv = server!();
    let mut other = srv.state.db.acquire().await.unwrap();
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(0x63_63_6d_61_69_6e_74_i64)
        .fetch_one(&mut *other)
        .await
        .unwrap();
    assert!(held);
    assert!(jobs::run_once(&srv.state).await.unwrap().skipped_locked);
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(0x63_63_6d_61_69_6e_74_i64)
        .execute(&mut *other)
        .await
        .unwrap();
    assert!(!jobs::run_once(&srv.state).await.unwrap().skipped_locked);
}
