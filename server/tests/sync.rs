// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Sync protocol (ADR-0003): sequences, revisions, conflicts, idempotency,
//! tombstones, paging, limits, concurrency.

mod common;

use cc_protocol::sync::{ChangesResponse, MutationResult, PushResponse, SnapshotResponse};
use cc_protocol::{paths, MutationId, ObjectId};
use common::*;
use reqwest::StatusCode;
use serde_json::json;
use std::collections::HashSet;

fn results(body: serde_json::Value) -> PushResponse {
    serde_json::from_value(body).expect("PushResponse")
}

#[tokio::test]
async fn revisions_sequences_and_conflicts() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let o1 = ObjectId::new();
    let o2 = ObjectId::new();

    let (status, body) = srv.push(&a, vault.id, vec![put(o1, 0), put(o2, 0)]).await;
    assert_eq!(status, StatusCode::OK);
    let r = results(body);
    assert_eq!(r.latest_sequence, 2);
    assert!(matches!(
        r.results[0],
        MutationResult::Accepted {
            revision: 1,
            sequence: 1,
            replayed: false,
            ..
        }
    ));
    assert!(matches!(
        r.results[1],
        MutationResult::Accepted {
            revision: 1,
            sequence: 2,
            ..
        }
    ));

    // Update o1 on the right base; o2 on a stale base → 409 with metadata,
    // but the accepted mutation in the same batch commits.
    let (status, body) = srv.push(&a, vault.id, vec![put(o1, 1), put(o2, 0)]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let r = results(body);
    assert_eq!(r.latest_sequence, 3);
    assert!(matches!(
        r.results[0],
        MutationResult::Accepted {
            revision: 2,
            sequence: 3,
            ..
        }
    ));
    match &r.results[1] {
        MutationResult::Conflict {
            object_id,
            current_revision,
            current_sequence,
            current_deleted,
            ..
        } => {
            assert_eq!(*object_id, o2);
            assert_eq!(*current_revision, 1);
            assert_eq!(*current_sequence, 2);
            assert!(!current_deleted);
        }
        other => panic!("expected conflict, got {other:?}"),
    }

    // Update of a never-created object with base 3 → conflict, current 0.
    let (status, body) = srv.push(&a, vault.id, vec![put(ObjectId::new(), 3)]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(matches!(
        results(body).results[0],
        MutationResult::Conflict {
            current_revision: 0,
            current_sequence: 0,
            ..
        }
    ));

    // Create of an existing object (base 0) → conflict.
    let (status, _) = srv.push(&a, vault.id, vec![put(o1, 0)]).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Pull: each object once, latest state, ordered by sequence.
    let (status, body) = srv.changes(&a, vault.id, 0).await;
    assert_eq!(status, StatusCode::OK);
    let c: ChangesResponse = serde_json::from_value(body).unwrap();
    let seqs: Vec<i64> = c.changes.iter().map(|x| x.sequence).collect();
    assert_eq!(seqs, vec![2, 3]);
    assert_eq!(c.latest_sequence, 3);
    let (_, body) = srv.changes(&a, vault.id, 2).await;
    let c: ChangesResponse = serde_json::from_value(body).unwrap();
    assert_eq!(c.changes.len(), 1);
    assert_eq!(c.changes[0].object_id, o1);
    assert_eq!(c.changes[0].revision, 2);
}

#[tokio::test]
async fn idempotent_replay() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let m = put(ObjectId::new(), 0);

    let (status, body) = srv.push(&a, vault.id, vec![m.clone()]).await;
    assert_eq!(status, StatusCode::OK);
    let first = results(body);
    // Retry of the same mutation (e.g. lost response): same result, replayed.
    let (status, body) = srv.push(&a, vault.id, vec![m.clone()]).await;
    assert_eq!(status, StatusCode::OK);
    let second = results(body);
    match (&first.results[0], &second.results[0]) {
        (
            MutationResult::Accepted {
                revision: r1,
                sequence: s1,
                replayed: false,
                ..
            },
            MutationResult::Accepted {
                revision: r2,
                sequence: s2,
                replayed: true,
                ..
            },
        ) => {
            assert_eq!((r1, s1), (r2, s2));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        second.latest_sequence, 1,
        "replay must not allocate a sequence"
    );

    // Reusing the mutation id for another object → 400, nothing applied.
    let mut other = put(ObjectId::new(), 0);
    other.mutation_id = m.mutation_id;
    let (status, body) = srv
        .push(&a, vault.id, vec![put(ObjectId::new(), 0), other])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        1
    );
}

#[tokio::test]
async fn tombstones_and_resurrection() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let o = ObjectId::new();
    srv.push(&a, vault.id, vec![put(o, 0)]).await;
    let (status, _) = srv.push(&a, vault.id, vec![delete(o, 1)]).await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = srv.changes(&a, vault.id, 0).await;
    let c: ChangesResponse = serde_json::from_value(body).unwrap();
    assert_eq!(c.changes.len(), 1);
    assert!(c.changes[0].deleted);
    assert!(c.changes[0].body.is_none());
    assert_eq!(c.changes[0].revision, 2);

    // Snapshot excludes tombstones.
    let (_, body) = srv
        .get(
            &format!("{}?vault_id={}", paths::SYNC_SNAPSHOT, vault.id),
            &a.access,
        )
        .await;
    let s: SnapshotResponse = serde_json::from_value(body).unwrap();
    assert!(s.objects.is_empty());
    assert_eq!(s.latest_sequence, 2);

    // Stale edit on a tombstone → conflict reporting deletion.
    let (status, body) = srv.push(&a, vault.id, vec![put(o, 1)]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(matches!(
        results(body).results[0],
        MutationResult::Conflict {
            current_revision: 2,
            current_deleted: true,
            ..
        }
    ));
    // Edit on top of the tombstone resurrects.
    let (status, _) = srv.push(&a, vault.id, vec![put(o, 2)]).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = srv.changes(&a, vault.id, 2).await;
    let c: ChangesResponse = serde_json::from_value(body).unwrap();
    assert!(!c.changes[0].deleted);
    assert_eq!(c.changes[0].revision, 3);
}

#[tokio::test]
async fn paging_changes_and_snapshot() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let batch: Vec<_> = (0..25).map(|_| put(ObjectId::new(), 0)).collect();
    let (status, _) = srv.push(&a, vault.id, batch).await;
    assert_eq!(status, StatusCode::OK);

    let mut after = 0;
    let mut seen = Vec::new();
    loop {
        let (status, body) = srv
            .get(
                &format!(
                    "{}?vault_id={}&after={after}&limit=10",
                    paths::SYNC_CHANGES,
                    vault.id
                ),
                &a.access,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let c: ChangesResponse = serde_json::from_value(body).unwrap();
        seen.extend(c.changes.iter().map(|x| x.sequence));
        after = c.next_after;
        if !c.has_more {
            break;
        }
    }
    assert_eq!(seen, (1..=25).collect::<Vec<_>>());

    let mut cursor: Option<i64> = None;
    let mut count = 0;
    loop {
        let q = match cursor {
            Some(c) => format!(
                "{}?vault_id={}&cursor={c}&limit=7",
                paths::SYNC_SNAPSHOT,
                vault.id
            ),
            None => format!("{}?vault_id={}&limit=7", paths::SYNC_SNAPSHOT, vault.id),
        };
        let (_, body) = srv.get(&q, &a.access).await;
        let s: SnapshotResponse = serde_json::from_value(body).unwrap();
        count += s.objects.len();
        match s.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(count, 25);

    // Invalid queries.
    let (status, _) = srv
        .get(
            &format!("{}?vault_id={}&after=-1", paths::SYNC_CHANGES, vault.id),
            &a.access,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = srv
        .get(
            &format!("{}?vault_id=nope&after=0", paths::SYNC_CHANGES),
            &a.access,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn page_byte_budget() {
    let srv = server!(|c| c.sync_page_bytes = 10 * 1024);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let batch: Vec<_> = (0..6)
        .map(|_| {
            let mut m = put(ObjectId::new(), 0);
            m.op = cc_protocol::sync::MutationOp::Put { body: body(4096) };
            m
        })
        .collect();
    srv.push(&a, vault.id, batch).await;
    let (_, body) = srv.changes(&a, vault.id, 0).await;
    let c: ChangesResponse = serde_json::from_value(body).unwrap();
    assert!(c.changes.len() < 6 && !c.changes.is_empty());
    assert!(c.has_more);
}

#[tokio::test]
async fn validation_and_limits() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let o = ObjectId::new();

    // Duplicate object in one batch.
    let (status, _) = srv.push(&a, vault.id, vec![put(o, 0), put(o, 0)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Negative base revision.
    let (status, _) = srv.push(&a, vault.id, vec![put(o, -1)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Malformed body (nonce length).
    let mut m = put(o, 0);
    if let cc_protocol::sync::MutationOp::Put { body } = &mut m.op {
        body.nonce = cc_protocol::Bytes::new(vec![0; 12]);
    }
    let (status, _) = srv.push(&a, vault.id, vec![m]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Unsupported format.
    let mut m = put(o, 0);
    if let cc_protocol::sync::MutationOp::Put { body } = &mut m.op {
        body.format = 99;
    }
    let (status, _) = srv.push(&a, vault.id, vec![m]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Oversized object.
    let mut m = put(o, 0);
    m.op = cc_protocol::sync::MutationOp::Put {
        body: body(cc_protocol::limits::MAX_OBJECT_CIPHERTEXT_BYTES + 1),
    };
    let (status, body_) = srv.push(&a, vault.id, vec![m]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body_}");
    assert_eq!(body_["code"], "payload_too_large");
    // Too many mutations.
    let batch: Vec<_> = (0..=cc_protocol::limits::MAX_PUSH_BATCH)
        .map(|_| delete(ObjectId::new(), 0))
        .collect();
    let (status, _) = srv.push(&a, vault.id, batch).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // Body over the transport limit.
    let big: Vec<_> = (0..17)
        .map(|_| {
            let mut m = put(ObjectId::new(), 0);
            m.op = cc_protocol::sync::MutationOp::Put {
                body: body(1024 * 1024),
            };
            m
        })
        .collect();
    let (status, _) = srv.push(&a, vault.id, big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // Malformed JSON.
    let resp = srv
        .signed(
            srv.http.post(srv.url(paths::SYNC_PUSH)),
            &a.access,
            "POST",
            paths::SYNC_PUSH,
            b"{not json",
        )
        .bearer_auth(&a.access)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Nothing was applied by any of the above.
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        0
    );
}

#[tokio::test]
async fn device_id_must_match_token() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let (status, _) = srv
        .post(
            paths::SYNC_PUSH,
            Some(&a.access),
            &json!({
                "vault_id": vault.id,
                "device_id": cc_protocol::DeviceId::new(),
                "mutations": [put(ObjectId::new(), 0)],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn concurrent_pushes_get_gap_free_unique_sequences() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);

    let shared = ObjectId::new();
    srv.push(&a, vault.id, vec![put(shared, 0)]).await;

    let mut tasks = Vec::new();
    for i in 0..20 {
        let (access, device) = if i % 2 == 0 {
            (a.access.clone(), a.device.id)
        } else {
            (b.access.clone(), b.device.id)
        };
        // Each push: one new object + a competing edit of the shared object.
        let body = serde_json::to_vec(&json!({
            "vault_id": vault.id,
            "device_id": device,
            "mutations": [put(ObjectId::new(), 0), put(shared, 1)],
        }))
        .unwrap();
        let req = srv
            .signed(
                srv.http.post(srv.url(paths::SYNC_PUSH)),
                &access,
                "POST",
                paths::SYNC_PUSH,
                &body,
            )
            .bearer_auth(access)
            .header("content-type", "application/json")
            .body(body);
        tasks.push(tokio::spawn(async move {
            let resp = req.send().await.unwrap();
            let status = resp.status();
            (status, resp.json::<PushResponse>().await.unwrap())
        }));
    }
    let mut sequences = HashSet::new();
    let mut shared_winners = 0;
    for t in tasks {
        let (status, r) = t.await.unwrap();
        assert!(status == StatusCode::OK || status == StatusCode::CONFLICT);
        for res in r.results {
            match res {
                MutationResult::Accepted {
                    sequence,
                    object_id,
                    ..
                } => {
                    assert!(sequences.insert(sequence), "duplicate sequence {sequence}");
                    if object_id == shared {
                        shared_winners += 1;
                    }
                }
                MutationResult::Conflict { object_id, .. } => assert_eq!(object_id, shared),
            }
        }
    }
    // Exactly one edit of the shared object wins against base revision 1.
    assert_eq!(shared_winners, 1);
    // Gap-free: 1 (initial) + 20 new objects + 1 winner = 22.
    let mut all: Vec<i64> = sequences.into_iter().collect();
    all.sort();
    assert_eq!(all, (2..=22).collect::<Vec<_>>());
    assert_eq!(
        srv.db_scalar_i64("SELECT last_sequence FROM vault_sequences")
            .await,
        22
    );
}

#[tokio::test]
async fn offline_mutations_sync_after_reconnect() {
    // A client queues mutations offline and pushes its outbox after
    // reconnecting; a partially delivered batch is retried with the same
    // mutation ids. (One object appears at most once per batch — ADR-0003.)
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let (o1, o2, o3) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    let batch1 = vec![put(o1, 0), put(o2, 0), put(o3, 0)];
    // First delivery attempt got only the first two through.
    srv.push(&a, vault.id, batch1[..2].to_vec()).await;
    let (status, body) = srv.push(&a, vault.id, batch1.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let r = results(body);
    let replayed: Vec<bool> = r
        .results
        .iter()
        .map(|x| matches!(x, MutationResult::Accepted { replayed: true, .. }))
        .collect();
    assert_eq!(replayed, vec![true, true, false]);
    assert_eq!(r.latest_sequence, 3);
    // Next outbox batch builds on the accepted revisions.
    let (status, body) = srv
        .push(&a, vault.id, vec![put(o1, 1), delete(o2, 1)])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(results(body).latest_sequence, 5);
    let _ = MutationId::new();
}

#[tokio::test]
async fn multi_megabyte_push_is_accepted() {
    // The push route raises the 1 MiB default body limit to 16 MiB.
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let batch: Vec<_> = (0..4)
        .map(|_| {
            let mut m = put(ObjectId::new(), 0);
            m.op = cc_protocol::sync::MutationOp::Put {
                body: body(cc_protocol::limits::MAX_OBJECT_CIPHERTEXT_BYTES),
            };
            m
        })
        .collect();
    let (status, body) = srv.push(&a, vault.id, batch).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Other endpoints keep the 1 MiB limit.
    let resp = srv
        .http
        .post(srv.url(paths::AUTH_LOGIN))
        .header("content-type", "application/json")
        .body(vec![b' '; 2 * 1024 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn vault_storage_quota() {
    let srv = server!(|c| c.max_vault_bytes = 10_000);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let big = |object_id, base| {
        let mut m = put(object_id, base);
        m.op = cc_protocol::sync::MutationOp::Put { body: body(4_000) };
        m
    };
    let (o1, o2, o3) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    assert_eq!(
        srv.push(&a, vault.id, vec![big(o1, 0), big(o2, 0)]).await.0,
        StatusCode::OK
    );
    // A third 4 KB object would exceed 10 KB: whole request refused.
    let (s, body_) = srv.push(&a, vault.id, vec![big(o3, 0)]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{body_}");
    assert_eq!(body_["details"]["reason"], "vault_quota");
    // Replacing an object in place is fine (net zero); deleting frees space.
    assert_eq!(
        srv.push(&a, vault.id, vec![big(o1, 1)]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        srv.push(&a, vault.id, vec![delete(o2, 1)]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        srv.push(&a, vault.id, vec![big(o3, 0)]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT stored_bytes FROM vault_sequences")
            .await,
        srv.db_scalar_i64("SELECT sum(octet_length(ciphertext))::bigint FROM vault_objects")
            .await
    );
}

#[tokio::test]
async fn vaults_per_account_quota() {
    let srv = server!(|c| c.max_vaults_per_account = 2);
    let a = srv.new_account().await;
    srv.create_vault(&a).await;
    let second = srv.create_vault(&a).await;
    let (s, body_) = srv
        .post(
            paths::VAULTS,
            Some(&a.access),
            &TestVault::new().create_request(a.device.id),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body_["details"]["reason"], "vault_limit");
    // Deleting one frees a slot.
    srv.delete(
        &paths::fill(paths::VAULT, &[("vault_id", &second.id.to_string())]),
        &a.access,
        Some(&json!({"vault_access_key": second.vak_bytes()})),
    )
    .await;
    srv.create_vault(&a).await;
}
