// SPDX-License-Identifier: AGPL-3.0-only
//! Protocol 1.8: owner-only delete with a restore window, recipients leaving.
mod common;
use cc_protocol::{sharing::*, ErrorCode, ShareId};
use common::{sharing::*, *};
use consolecrypt_server::{jobs, sharing::service};
use reqwest::StatusCode;
use serde_json::json;
use uuid::Uuid;

fn tombstone(writer: &Session, old: &SharedItemState) -> PutSharedRevisionRequest {
    let mut delete = revision(writer, &old.access.manifest, Some(&old.revision));
    delete.signed.mutation.operation = SharingOperation::Delete;
    delete.body = None;
    sign_revision(writer, &mut delete);
    PutSharedRevisionRequest { revision: delete }
}

async fn restore_request(
    srv: &TestServer,
    owner: &Session,
    others: &[(&Session, SharingRole)],
    from: ShareId,
) -> CreateShareRequest {
    let mut req = request(srv, owner, others).await;
    req.restored_from = Some(from);
    req
}

#[tokio::test]
async fn editor_cannot_delete_the_owners_item() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(&srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = old.access.manifest.share_id;
    assert_eq!(
        service::put(&srv.state, &context(&editor), id, tombstone(&editor, &old))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::OwnerOnly
    );
    // An old client gets a plain 403 with the new code, never data loss.
    let (code, body) = srv
        .post(
            &format!("{}/revisions", path(id)),
            Some(&editor.access),
            &tombstone(&editor, &old),
        )
        .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "owner_only");
    assert_eq!(
        service::get(&srv.state, &context(&owner), id)
            .await
            .unwrap(),
        old
    );
    // Editing stays allowed for editors.
    let edit = PutSharedRevisionRequest {
        revision: revision(&editor, &old.access.manifest, Some(&old.revision)),
    };
    service::put(&srv.state, &context(&editor), id, edit)
        .await
        .unwrap();
    let (_, meta) = srv.get("/v1/meta", &owner.access).await;
    assert_eq!(meta["protocol_version"], "1.11");
    assert_eq!(meta["capabilities"]["share_leave"], true);
    assert_eq!(meta["capabilities"]["share_restore"], true);
    let off = server!();
    let (_, meta) = off.get("/v1/meta", &owner.access).await;
    assert_eq!(meta["capabilities"]["share_leave"], false);
}

#[tokio::test]
async fn owner_delete_is_restorable_once_within_the_window() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(&srv, &owner, &[(&editor, SharingRole::Editor)]).await;
    let id = old.access.manifest.share_id;
    let deleted = service::put(&srv.state, &context(&owner), id, tombstone(&owner, &old))
        .await
        .unwrap();
    // Recipients see the signed tombstone and lose the content.
    let seen = service::get(&srv.state, &context(&editor), id)
        .await
        .unwrap();
    assert_eq!(seen, deleted);
    assert!(seen.revision.body.is_none());
    // Only the owner lists the retained last content.
    let (code, page) = srv.get(DELETED_PATH, &owner.access).await;
    assert_eq!(code, StatusCode::OK);
    let page: DeletedShareListPage = serde_json::from_value(page).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].state, deleted);
    assert_eq!(page.items[0].last_revision, old.revision);
    assert_eq!(
        page.items[0].restorable_until - page.items[0].deleted_at,
        chrono::Duration::days(30)
    );
    let (_, other) = srv.get(DELETED_PATH, &editor.access).await;
    assert!(other["items"].as_array().unwrap().is_empty());
    // A stranger cannot claim it; the owner republishes it once.
    let stranger = srv.new_account().await;
    assert_eq!(
        service::create(
            &srv.state,
            &context(&stranger),
            restore_request(&srv, &stranger, &[], id).await
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::NotFound
    );
    let req = restore_request(&srv, &owner, &[(&editor, SharingRole::Editor)], id).await;
    let (code, _) = srv.post("/v1/shares", Some(&owner.access), &req).await;
    assert_eq!(code, StatusCode::CREATED);
    assert!(srv.get(DELETED_PATH, &owner.access).await.1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        service::create(
            &srv.state,
            &context(&owner),
            restore_request(&srv, &owner, &[], id).await
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Gone
    );
    // The old tombstone stays final.
    let again = PutSharedRevisionRequest {
        revision: revision(&owner, &deleted.access.manifest, Some(&deleted.revision)),
    };
    assert_eq!(
        service::put(&srv.state, &context(&owner), id, again)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Gone
    );
}

#[tokio::test]
async fn restore_window_expires_and_quota_counts_restorable_items() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let old = create(&srv, &owner, &[]).await;
    let id = old.access.manifest.share_id;
    service::put(&srv.state, &context(&owner), id, tombstone(&owner, &old))
        .await
        .unwrap();
    let live =
        "SELECT count(*) FROM shared_items WHERE NOT deleted OR restore_revision IS NOT NULL";
    assert_eq!(srv.db_scalar_i64(live).await, 1);
    sqlx::query("UPDATE shared_items SET deleted_at = now() - interval '31 days' WHERE id=$1")
        .bind(Uuid::from(id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert!(srv.get(DELETED_PATH, &owner.access).await.1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        service::create(
            &srv.state,
            &context(&owner),
            restore_request(&srv, &owner, &[], id).await
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Gone
    );
    let report = jobs::run_once(&srv.state).await.unwrap();
    assert_eq!(report.shared_restores_expired, 1);
    assert_eq!(srv.db_scalar_i64(live).await, 0);
    // The signed tombstone itself is kept for recipients.
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_items WHERE deleted")
            .await,
        1
    );
}

#[tokio::test]
async fn recipient_leaves_and_owner_sees_the_departure() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let editor = srv.new_account().await;
    let old = create(
        &srv,
        &owner,
        &[
            (&reader, SharingRole::Reader),
            (&editor, SharingRole::Editor),
        ],
    )
    .await;
    let id = old.access.manifest.share_id;
    let leave = format!("{}/leave", path(id));
    let (code, body) = srv.post(&leave, Some(&owner.access), &json!({})).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body}");
    let stranger = srv.new_account().await;
    assert_eq!(
        srv.post(&leave, Some(&stranger.access), &json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.post(&leave, Some(&reader.access), &json!({})).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        srv.post(&leave, Some(&reader.access), &json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.get(&path(id), &reader.access).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(srv.get("/v1/shares", &reader.access).await.1["items"]
        .as_array()
        .unwrap()
        .is_empty());
    let (_, page) = srv.get("/v1/shares", &owner.access).await;
    let page: ShareListPage = serde_json::from_value(page).unwrap();
    assert_eq!(
        page.departures,
        vec![ShareDeparture {
            share_id: id,
            user_id: reader.user_id
        }]
    );
    // Other recipients never learn about departures.
    let (_, page) = srv.get("/v1/shares", &editor.access).await;
    assert!(page.get("departures").is_none());
    // A stale owner manifest keeping the device does not let it back in.
    let members = old.access.manifest.members.clone();
    let kept = service::rotate(
        &srv.state,
        &context(&owner),
        id,
        rotation(&owner, &old, members.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.get(&path(id), &reader.access).await.0,
        StatusCode::NOT_FOUND
    );
    // Dropping the account acknowledges the departure.
    let dropped: Vec<_> = members
        .iter()
        .filter(|m| m.user_id != reader.user_id)
        .cloned()
        .collect();
    let next = service::rotate(
        &srv.state,
        &context(&owner),
        id,
        rotation(&owner, &kept, dropped),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_item_departures")
            .await,
        0
    );
    // A later explicit invitation works again.
    service::rotate(
        &srv.state,
        &context(&owner),
        id,
        rotation(&owner, &next, members),
    )
    .await
    .unwrap();
    assert_eq!(srv.get(&path(id), &reader.access).await.0, StatusCode::OK);
}

#[tokio::test]
async fn restore_never_re_adds_a_recipient_who_left() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let old = create(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let id = old.access.manifest.share_id;
    service::leave(&srv.state, &context(&reader), id)
        .await
        .unwrap();
    service::put(&srv.state, &context(&owner), id, tombstone(&owner, &old))
        .await
        .unwrap();
    let (_, page) = srv.get(DELETED_PATH, &owner.access).await;
    let page: DeletedShareListPage = serde_json::from_value(page).unwrap();
    assert_eq!(page.items[0].departed_user_ids, vec![reader.user_id]);
    assert_eq!(
        service::create(
            &srv.state,
            &context(&owner),
            restore_request(&srv, &owner, &[(&reader, SharingRole::Reader)], id).await
        )
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Forbidden
    );
    service::create(
        &srv.state,
        &context(&owner),
        restore_request(&srv, &owner, &[], id).await,
    )
    .await
    .unwrap();
}
