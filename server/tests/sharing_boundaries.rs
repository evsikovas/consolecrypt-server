// SPDX-License-Identifier: AGPL-3.0-only
//! S07-S09 baseline: reserved kinds and delegation stay closed until a reviewed
//! additive contract exists. All bytes remain the current sharing format1.
mod common;
use cc_protocol::{sharing::*, ErrorCode};
use common::sharing::*;
use consolecrypt_server::sharing::service;
use reqwest::StatusCode;

#[tokio::test]
async fn both_reserved_content_kinds_remain_closed_on_create_and_rotation() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let current = create(&srv, &owner, &[]).await;
    let id = current.access.manifest.share_id;
    for kind in [SharedItemKind::Group, SharedItemKind::Secret] {
        let mut draft = request(&srv, &owner, &[]).await;
        draft.access.manifest.kind = kind;
        draft.access = sign_manifest(&owner, draft.access.manifest);
        draft.revision = revision(&owner, &draft.access.manifest, None);
        assert_eq!(
            srv.post("/v1/shares", Some(&owner.access), &draft).await.0,
            StatusCode::BAD_REQUEST
        );
        let mut change = rotation(&owner, &current, current.access.manifest.members.clone());
        change.access.manifest.kind = kind;
        change.access = sign_manifest(&owner, change.access.manifest);
        change.revision = revision(&owner, &change.access.manifest, Some(&current.revision));
        assert_eq!(
            service::rotate(&srv.state, &context(&owner), id, change)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::BadRequest
        );
    }
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap(),
        current
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_items").await,
        1
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_manifests")
            .await,
        1
    );
}

#[tokio::test]
async fn editor_cannot_relay_owner_signed_rotation_to_add_its_own_device() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let sibling = srv
        .new_device_session(&editor, "new recipient device")
        .await;
    let current = create(&srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = current.access.manifest.share_id;
    let mut members = current.access.manifest.members.clone();
    members.push(member(&sibling, SharingRole::Editor));
    // Even an intact owner-signed next manifest does not give the editor a
    // general access-rotation route. The author of its new body is the editor.
    let mut change = rotation(&owner, &current, members);
    change.revision = revision(&editor, &change.access.manifest, Some(&current.revision));
    assert_eq!(
        service::rotate(&srv.state, &context(&editor), id, change)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Forbidden
    );
    assert_eq!(
        service::get(&srv.state, &context(&sibling), id)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap(),
        current
    );
}

#[tokio::test]
async fn reader_cannot_rotate_ciphertext_under_enrollment_or_removal_pretext() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let sibling = srv
        .new_device_session(&reader, "unapproved reader device")
        .await;
    let current = create(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let id = current.access.manifest.share_id;
    let mut members = current.access.manifest.members.clone();
    members.push(member(&sibling, SharingRole::Reader));
    let mut change = rotation(&owner, &current, members);
    change.revision = revision(&reader, &change.access.manifest, Some(&current.revision));
    assert_eq!(
        service::rotate(&srv.state, &context(&reader), id, change)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Forbidden
    );
    let mut rewrite = rotation(&owner, &current, current.access.manifest.members.clone());
    rewrite.revision = revision(&reader, &rewrite.access.manifest, Some(&current.revision));
    assert_eq!(
        service::rotate(&srv.state, &context(&reader), id, rewrite)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Forbidden
    );
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap(),
        current
    );
}

#[tokio::test]
async fn personal_vault_trust_never_enrolls_a_device_in_shared_items() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let recipient = srv.new_account().await;
    let sibling = srv
        .new_device_session(&recipient, "personal vault trusted")
        .await;
    let personal = srv.create_vault(&recipient).await;
    assert_eq!(srv.attest(&sibling, &personal).await.0, StatusCode::OK);
    let current = create(&srv, &owner, &[(&recipient, SharingRole::Editor)]).await;
    let id = current.access.manifest.share_id;
    assert_eq!(
        service::get(&srv.state, &context(&sibling), id)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert!(service::list(&srv.state, &context(&sibling), None, 100)
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        srv.get(&format!("{}/history", path(id)), &sibling.access)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_item_devices")
            .await,
        2
    );
}

#[tokio::test]
async fn approved_owner_sibling_cannot_inherit_the_pinned_owner_authority() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let sibling = srv.new_device_session(&owner, "owner editor sibling").await;
    let stranger = srv.new_account().await;
    let current = create(&srv, &owner, &[(&sibling, SharingRole::Editor)]).await;
    let id = current.access.manifest.share_id;
    let mut members = current.access.manifest.members.clone();
    members.push(member(&stranger, SharingRole::Reader));
    let mut change = rotation(&owner, &current, members);
    change.revision = revision(&sibling, &change.access.manifest, Some(&current.revision));
    assert_eq!(
        service::rotate(&srv.state, &context(&sibling), id, change)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Forbidden
    );
    assert_eq!(
        service::get(&srv.state, &context(&stranger), id)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap(),
        current
    );
}
