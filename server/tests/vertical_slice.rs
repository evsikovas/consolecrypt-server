// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! First end-to-end milestone (PARALLEL_AGENTS_PROMPT): register → create
//! vault → push ciphertext → second device logs in → gets the password
//! envelope → attests with the vault access key → pulls the ciphertext.

mod common;

use cc_protocol::envelopes::RecipientType;
use cc_protocol::sync::{ChangesResponse, MutationOp, PushResponse, SnapshotResponse};
use cc_protocol::vaults::{ListEnvelopesResponse, ListVaultsResponse, VaultInfo};
use cc_protocol::{paths, ObjectId};
use common::*;
use reqwest::StatusCode;

#[tokio::test]
async fn register_create_push_second_device_attest_pull() {
    let srv = server!();

    // Device A: register and create a vault.
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;

    // Push one encrypted object.
    let object_id = ObjectId::new();
    let m = put(object_id, 0);
    let pushed_body = match &m.op {
        MutationOp::Put { body } => body.clone(),
        MutationOp::Delete => unreachable!(),
    };
    let (status, body) = srv.push(&a, vault.id, vec![m]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let push: PushResponse = serde_json::from_value(body).unwrap();
    assert_eq!(push.latest_sequence, 1);

    // Device B: log in to the same account (new, untrusted device).
    let b = srv.new_device_session(&a, "Device B").await;

    // B sees the vault but is not trusted.
    let (status, body) = srv.get(paths::VAULTS, &b.access).await;
    assert_eq!(status, StatusCode::OK);
    let list: ListVaultsResponse = serde_json::from_value(body).unwrap();
    assert_eq!(list.vaults.len(), 1);
    assert_eq!(list.vaults[0].vault_id, vault.id);
    assert!(!list.vaults[0].caller_trusted);
    assert_eq!(list.vaults[0].latest_sequence, 1);

    // B gets only the unlock material (password + recovery), not A's device envelope.
    let path = paths::fill(
        paths::VAULT_ENVELOPES,
        &[("vault_id", &vault.id.to_string())],
    );
    let (status, body) = srv.get(&path, &b.access).await;
    assert_eq!(status, StatusCode::OK);
    let envs: ListEnvelopesResponse = serde_json::from_value(body).unwrap();
    let mut types: Vec<_> = envs.envelopes.iter().map(|e| e.recipient_type).collect();
    types.sort_by_key(|t| format!("{t:?}"));
    assert_eq!(
        types,
        vec![RecipientType::Password, RecipientType::Recovery]
    );

    // Untrusted B cannot pull yet.
    let (status, body) = srv.changes(&b, vault.id, 0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "device_not_trusted");

    // B unlocks locally (passphrase) and attests with the vault access key.
    let (status, body) = srv.attest(&b, &vault).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recipient_type"], "device");

    // Now B pulls the exact ciphertext A pushed.
    let (status, body) = srv.changes(&b, vault.id, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let changes: ChangesResponse = serde_json::from_value(body).unwrap();
    assert_eq!(changes.changes.len(), 1);
    let c = &changes.changes[0];
    assert_eq!(c.object_id, object_id);
    assert_eq!(c.revision, 1);
    assert_eq!(c.sequence, 1);
    assert_eq!(c.writer_device_id, a.device.id);
    assert_eq!(c.body.as_ref().unwrap(), &pushed_body);
    assert_eq!(changes.next_after, 1);
    assert!(!changes.has_more);

    // Snapshot gives the same object.
    let (status, body) = srv
        .get(
            &format!("{}?vault_id={}", paths::SYNC_SNAPSHOT, vault.id),
            &b.access,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let snap: SnapshotResponse = serde_json::from_value(body).unwrap();
    assert_eq!(snap.objects.len(), 1);
    assert!(snap.next_cursor.is_none());

    // And B now shows as trusted.
    let (_, body) = srv
        .get(
            &paths::fill(paths::VAULT, &[("vault_id", &vault.id.to_string())]),
            &b.access,
        )
        .await;
    let info: VaultInfo = serde_json::from_value(body).unwrap();
    assert!(info.caller_trusted);
}

#[tokio::test]
async fn attest_with_wrong_access_key_is_rejected() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "Device B").await;

    let wrong = TestVault {
        id: vault.id,
        vak: random::<32>(),
    };
    let (status, body) = srv.attest(&b, &wrong).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "invalid_proof");
    let (status, _) = srv.changes(&b, vault.id, 0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'device_attest_failed'"
        )
        .await,
        1
    );
}
