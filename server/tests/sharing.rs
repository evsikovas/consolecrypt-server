// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use cc_protocol::{sharing::*, ErrorCode};
use common::{sharing::*, *};
use consolecrypt_server::sharing::service;
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn default_off_and_http_signed_lifecycle() {
    let off = server!();
    let owner = off.new_account().await;
    assert_eq!(
        off.get("/v1/shares/capabilities", &owner.access).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(service::create(
        &off.state,
        &context(&owner),
        request(&off, &owner, &[]).await
    )
    .await
    .is_err());
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let (code, caps) = srv.get("/v1/shares/capabilities", &owner.access).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(caps["enabled"], true);
    let req = request(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let id = req.access.manifest.share_id;
    let (code, body) = srv.post("/v1/shares", Some(&owner.access), &req).await;
    assert_eq!(code, StatusCode::CREATED);
    let old: SharedItemState = serde_json::from_value(body).unwrap();
    assert_eq!(srv.get(&path(id), &reader.access).await.0, StatusCode::OK);
    let update = PutSharedRevisionRequest {
        revision: revision(&owner, &old.access.manifest, Some(&old.revision)),
    };
    assert_eq!(
        srv.post(
            &format!("{}/revisions", path(id)),
            Some(&owner.access),
            &update
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, h) = srv
        .get(&format!("{}/history", path(id)), &reader.access)
        .await;
    assert_eq!(h["revisions"].as_array().unwrap().len(), 2);
    assert!(!h.to_string().contains("ciphertext"));
    assert!(!h.to_string().contains("envelopes"));
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_members")
            .await,
        0
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_key_envelopes")
            .await,
        0
    );
    assert_eq!(
        srv.get("/v1/meta", &owner.access).await.1["protocol_version"],
        "1.5"
    );
}
#[tokio::test]
async fn idor_unapproved_sibling_and_reader_write_are_denied() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let stranger = srv.new_account().await;
    let sibling = srv.new_device_session(&reader, "unapproved").await;
    let old = create(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let id = old.access.manifest.share_id;
    for s in [&stranger, &sibling] {
        assert_eq!(srv.get(&path(id), &s.access).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            srv.get(&format!("{}/history", path(id)), &s.access).await.0,
            StatusCode::NOT_FOUND
        );
        assert!(srv.get("/v1/shares", &s.access).await.1["items"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    let edit = PutSharedRevisionRequest {
        revision: revision(&reader, &old.access.manifest, Some(&old.revision)),
    };
    assert_eq!(
        service::put(&srv.state, &context(&reader), id, edit)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Forbidden
    );
    let mut delete = revision(&reader, &old.access.manifest, Some(&old.revision));
    delete.signed.mutation.operation = SharingOperation::Delete;
    delete.body = None;
    sign_revision(&reader, &mut delete);
    assert_eq!(
        service::put(
            &srv.state,
            &context(&reader),
            id,
            PutSharedRevisionRequest { revision: delete }
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Forbidden
    );
}
#[tokio::test]
async fn signatures_keys_instance_and_coverage_fail_closed() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let other = srv.new_account().await;
    let original = request(&srv, &owner, &[(&other, SharingRole::Reader)]).await;
    let mut cases = Vec::new();
    let mut bad = original.clone();
    bad.access.signature = random::<64>().to_vec().into();
    cases.push(bad);
    let mut bad = original.clone();
    bad.revision.signed.signature = random::<64>().to_vec().into();
    cases.push(bad);
    let mut bad = original.clone();
    bad.revision.body.as_mut().unwrap().ciphertext = random::<80>().to_vec().into();
    cases.push(bad);
    let mut bad = original.clone();
    bad.revision.body.as_mut().unwrap().envelopes.pop();
    sign_revision(&owner, &mut bad.revision);
    cases.push(bad);
    for mode in 0..4 {
        let mut bad = original.clone();
        match mode {
            0 => {
                bad.access.manifest.members[1].encryption_public_key =
                    random::<32>().to_vec().into()
            }
            1 => bad.access.manifest.members[1].user_id = owner.user_id,
            2 => bad.access.manifest.server_instance_id = Uuid::new_v4(),
            _ => bad.access.manifest.kind = SharedItemKind::Secret,
        }
        bad.access = sign_manifest(&owner, bad.access.manifest);
        bad.revision = revision(&owner, &bad.access.manifest, None);
        cases.push(bad);
    }
    for req in cases {
        assert!(service::create(&srv.state, &context(&owner), req)
            .await
            .is_err());
    }
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_items").await,
        0
    );
}
#[tokio::test]
async fn revoke_is_atomic_and_old_epochs_are_rejected() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(&srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = old.access.manifest.share_id;
    let stale = PutSharedRevisionRequest {
        revision: revision(&editor, &old.access.manifest, Some(&old.revision)),
    };
    let rotate = rotation(&owner, &old, vec![member(&owner, SharingRole::Editor)]);
    let mut bad = rotate.clone();
    bad.revision.body.as_mut().unwrap().ciphertext =
        old.revision.body.as_ref().unwrap().ciphertext.clone();
    sign_revision(&owner, &mut bad.revision);
    assert!(service::rotate(&srv.state, &context(&owner), id, bad)
        .await
        .is_err());
    assert_eq!(
        service::get(&srv.state, &context(&editor), id)
            .await
            .unwrap(),
        old
    );
    let next = service::rotate(&srv.state, &context(&owner), id, rotate)
        .await
        .unwrap();
    assert_eq!(next.access.manifest.access_epoch, 2);
    assert_eq!(
        service::get(&srv.state, &context(&editor), id)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert!(service::put(&srv.state, &context(&editor), id, stale)
        .await
        .is_err());
    let stale = PutSharedRevisionRequest {
        revision: revision(&owner, &old.access.manifest, Some(&old.revision)),
    };
    assert_eq!(
        service::put(&srv.state, &context(&owner), id, stale)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Conflict
    );
    let page = service::history(&srv.state, &context(&owner), id, 0, 0, 1)
        .await
        .unwrap();
    assert!(page.has_more);
    assert_eq!(page.manifests.len(), 1);
    let tail = service::history(&srv.state, &context(&owner), id, 1, 1, 100)
        .await
        .unwrap();
    assert!(!tail.has_more);
    assert_eq!(tail.manifests[0].manifest.revision, 2);
}
#[tokio::test]
async fn editor_cannot_replace_owner_and_tombstone_is_final() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(&srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = old.access.manifest.share_id;
    let mut forged = rotation(&owner, &old, old.access.manifest.members.clone());
    forged.access.manifest.owner_device_id = editor.device.id;
    forged.access.manifest.owner_user_id = editor.user_id;
    forged.access = sign_manifest(&editor, forged.access.manifest);
    forged.revision = revision(&editor, &forged.access.manifest, Some(&old.revision));
    assert!(service::rotate(&srv.state, &context(&editor), id, forged)
        .await
        .is_err());
    let mut delete = revision(&editor, &old.access.manifest, Some(&old.revision));
    delete.signed.mutation.operation = SharingOperation::Delete;
    delete.body = None;
    sign_revision(&editor, &mut delete);
    let deleted = service::put(
        &srv.state,
        &context(&editor),
        id,
        PutSharedRevisionRequest { revision: delete },
    )
    .await
    .unwrap();
    let restore = PutSharedRevisionRequest {
        revision: revision(&owner, &deleted.access.manifest, Some(&deleted.revision)),
    };
    assert_eq!(
        service::put(&srv.state, &context(&owner), id, restore)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Gone
    );
}
#[tokio::test]
async fn stale_auth_fails_after_identity_revocation_and_token_rotation() {
    for mode in 0..5 {
        let srv = server!(|c| c.object_sharing_enabled = true);
        let owner = srv.new_account().await;
        let old = create(&srv, &owner, &[]).await;
        let id = old.access.manifest.share_id;
        let auth = context(&owner);
        match mode {
            0 => {
                sqlx::query("UPDATE sessions SET revoked_at=now() WHERE id=$1")
                    .bind(Uuid::from(owner.session_id))
                    .execute(&srv.state.db)
                    .await
                    .unwrap();
            }
            1 => {
                sqlx::query("UPDATE sessions SET access_token_hash=$2 WHERE id=$1")
                    .bind(Uuid::from(owner.session_id))
                    .bind(random::<32>().to_vec())
                    .execute(&srv.state.db)
                    .await
                    .unwrap();
            }
            2 => {
                sqlx::query(
                    "UPDATE sessions SET access_expires_at=now()-interval '1 second' WHERE id=$1",
                )
                .bind(Uuid::from(owner.session_id))
                .execute(&srv.state.db)
                .await
                .unwrap();
            }
            3 => {
                sqlx::query("UPDATE devices SET revoked_at=now() WHERE id=$1")
                    .bind(Uuid::from(owner.device.id))
                    .execute(&srv.state.db)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
                    .bind(Uuid::from(owner.user_id))
                    .execute(&srv.state.db)
                    .await
                    .unwrap();
            }
        }
        assert!(service::get(&srv.state, &auth, id).await.is_err());
        assert!(service::put(
            &srv.state,
            &auth,
            id,
            PutSharedRevisionRequest {
                revision: revision(&owner, &old.access.manifest, Some(&old.revision))
            }
        )
        .await
        .is_err());
    }
}
#[tokio::test]
async fn globally_revoked_recipient_blocks_new_keys_but_owner_can_rotate() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let other = srv.new_account().await;
    let old = create(&srv, &owner, &[(&other, SharingRole::Reader)]).await;
    let id = old.access.manifest.share_id;
    assert_eq!(
        srv.post(
            &format!("/v1/devices/{}/revoke", other.device.id),
            Some(&other.access),
            &json!({})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(service::put(
        &srv.state,
        &context(&owner),
        id,
        PutSharedRevisionRequest {
            revision: revision(&owner, &old.access.manifest, Some(&old.revision))
        }
    )
    .await
    .is_err());
    assert!(service::get(&srv.state, &context(&owner), id).await.is_ok());
    assert!(service::rotate(
        &srv.state,
        &context(&owner),
        id,
        rotation(&owner, &old, vec![member(&owner, SharingRole::Editor)])
    )
    .await
    .is_ok());
}
#[tokio::test]
async fn recipient_lookup_requires_verified_accounts() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let other = srv.new_account().await;
    assert_eq!(
        service::recipient(&srv.state, &context(&owner), &other.email)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::EmailNotVerified
    );
    sqlx::query("UPDATE users SET email_verified_at=now() WHERE id=$1")
        .bind(Uuid::from(owner.user_id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(
        service::recipient(&srv.state, &context(&owner), &other.email)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    sqlx::query("UPDATE users SET email_verified_at=now() WHERE id=$1")
        .bind(Uuid::from(other.user_id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    let found = service::recipient(&srv.state, &context(&owner), &other.email)
        .await
        .unwrap();
    assert_eq!(found.devices[0].device_id, other.device.id);
    assert_eq!(found.devices[0].role, SharingRole::Reader);
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_item_devices")
            .await,
        0
    );
}

#[tokio::test]
async fn http_proofs_and_large_body_limit_are_enforced() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let response = srv
        .http
        .get(srv.url("/v1/shares"))
        .bearer_auth(&owner.access)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let mut req = request(&srv, &owner, &[]).await;
    let mut opaque = vec![0u8; MAX_CIPHERTEXT_BYTES];
    getrandom::fill(&mut opaque).unwrap();
    req.revision.body.as_mut().unwrap().ciphertext = opaque.into();
    sign_revision(&owner, &mut req.revision);
    assert_eq!(
        srv.post("/v1/shares", Some(&owner.access), &req).await.0,
        StatusCode::CREATED
    );
    let mut too_big = req.clone();
    too_big.access.manifest.share_id = cc_protocol::ShareId::new();
    too_big.access = sign_manifest(&owner, too_big.access.manifest);
    too_big.revision = revision(&owner, &too_big.access.manifest, None);
    too_big.revision.body.as_mut().unwrap().ciphertext = vec![0; MAX_CIPHERTEXT_BYTES + 1].into();
    assert!(srv
        .post("/v1/shares", Some(&owner.access), &too_big)
        .await
        .0
        .is_client_error());
}

#[tokio::test]
async fn mutation_reuse_and_pinned_key_substitution_roll_back() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let old = create(&srv, &owner, &[]).await;
    let id = old.access.manifest.share_id;
    let mut reused = revision(&owner, &old.access.manifest, Some(&old.revision));
    reused.signed.mutation.mutation_id = old.revision.signed.mutation.mutation_id;
    sign_revision(&owner, &mut reused);
    assert_eq!(
        service::put(
            &srv.state,
            &context(&owner),
            id,
            PutSharedRevisionRequest { revision: reused }
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Conflict
    );
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap(),
        old
    );
    sqlx::query("UPDATE devices SET encryption_public_key=$2 WHERE id=$1")
        .bind(Uuid::from(owner.device.id))
        .bind(random::<32>().to_vec())
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::InvalidProof
    );
}

#[tokio::test]
async fn list_byte_budget_keeps_the_unread_item_for_next_page() {
    let srv = server!(|c| {
        c.object_sharing_enabled = true;
        c.sync_page_bytes = 1024;
    });
    let owner = srv.new_account().await;
    let a = create(&srv, &owner, &[]).await;
    let b = create(&srv, &owner, &[]).await;
    let first = service::list(&srv.state, &context(&owner), None, 100)
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(first.has_more);
    let next = service::list(&srv.state, &context(&owner), first.next_after, 100)
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1);
    assert!(!next.has_more);
    let mut actual = vec![
        first.items[0].access.manifest.share_id,
        next.items[0].access.manifest.share_id,
    ];
    actual.sort();
    let mut expected = vec![a.access.manifest.share_id, b.access.manifest.share_id];
    expected.sort();
    assert_eq!(actual, expected);
}
