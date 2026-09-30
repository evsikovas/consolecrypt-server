// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! ADR-0009 kind gates and backward-compatible HTTP list negotiation.
//! Signatures are real; all opaque encrypted payloads/keys are generated at runtime.
mod common;

use cc_protocol::{sharing::*, ErrorCode, ShareId};
use common::{sharing::*, *};
use consolecrypt_server::{config::EventBusKind, sharing::service, AppState, Config};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

async fn kind_request(
    srv: &TestServer,
    owner: &Session,
    others: &[(&Session, SharingRole)],
    kind: SharedItemKind,
) -> CreateShareRequest {
    let mut req = request(srv, owner, others).await;
    req.access.manifest.kind = kind;
    req.access = sign_manifest(owner, req.access.manifest);
    req.revision = revision(owner, &req.access.manifest, None);
    req
}

async fn publish(srv: &TestServer, owner: &Session, req: &CreateShareRequest) -> SharedItemState {
    let (status, body) = srv.post("/v1/shares", Some(&owner.access), req).await;
    assert_eq!(status, StatusCode::CREATED);
    serde_json::from_value(body).expect("created SharedItemState")
}

async fn create_kind(
    srv: &TestServer,
    owner: &Session,
    others: &[(&Session, SharingRole)],
    kind: SharedItemKind,
) -> SharedItemState {
    publish(srv, owner, &kind_request(srv, owner, others, kind).await).await
}

async fn caps(srv: &TestServer, owner: &Session) -> Value {
    let (status, body) = srv.get("/v1/shares/capabilities", &owner.access).await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn paginated_ids(srv: &TestServer, caller: &Session, flags: &str) -> Vec<ShareId> {
    let mut after: Option<ShareId> = None;
    let mut ids = Vec::new();
    // Fixtures have seven rows. Empty filtered pages are allowed only with a
    // strictly advancing cursor; bound retries so a cursor bug cannot hang CI.
    for _ in 0..32 {
        let mut query = String::from("/v1/shares?limit=1");
        if !flags.is_empty() {
            query.push('&');
            query.push_str(flags);
        }
        if let Some(cursor) = after {
            query.push_str(&format!("&after={cursor}"));
        }
        let (status, body) = srv.get(&query, &caller.access).await;
        assert_eq!(status, StatusCode::OK);
        let page: ShareListPage = serde_json::from_value(body).expect("ShareListPage");
        assert!(page.items.len() <= 1);
        for item in page.items {
            let id = item.access.manifest.share_id;
            assert!(after.is_none_or(|cursor| id > cursor));
            assert!(ids.last().is_none_or(|previous| id > *previous));
            ids.push(id);
        }
        if !page.has_more {
            assert_eq!(page.next_after, None);
            return ids;
        }
        let next = page
            .next_after
            .expect("nonterminal page must have a cursor");
        assert!(after.is_none_or(|previous| next > previous));
        assert!(ids.last().is_none_or(|last| next >= *last));
        after = Some(next);
    }
    panic!("filtered sharing list did not terminate with bounded cursor progress");
}

#[test]
fn kind_flags_default_off_and_require_general_sharing_and_proofs() {
    let baseline = Config::for_tests("postgres://localhost/unused");
    assert!(!baseline.shared_groups_enabled);
    assert!(!baseline.shared_secrets_enabled);
    for groups in [false, true] {
        let mut config = baseline.clone();
        config.shared_groups_enabled = groups;
        config.shared_secrets_enabled = !groups;
        config.object_sharing_enabled = false;
        assert!(config.validate().is_err());
        config.object_sharing_enabled = true;
        config.require_request_proof = false;
        assert!(config.validate().is_err());
        config.require_request_proof = true;
        assert!(config.validate().is_ok());
    }
}

#[tokio::test]
async fn independent_flags_report_capabilities_and_gate_publication() {
    for (groups, secrets) in [(false, false), (true, false), (false, true), (true, true)] {
        let srv = server!(|c| {
            c.object_sharing_enabled = true;
            c.shared_groups_enabled = groups;
            c.shared_secrets_enabled = secrets;
        });
        let owner = srv.new_account().await;
        let capabilities = caps(&srv, &owner).await;
        assert_eq!(capabilities["supports_groups"], groups);
        assert_eq!(capabilities["supports_secrets"], secrets);
        assert_eq!(capabilities["supports_owner_online_enrollment_v1"], false);
        for (kind, enabled, flag) in [
            (SharedItemKind::Group, groups, "include_groups"),
            (SharedItemKind::Secret, secrets, "include_secrets"),
        ] {
            let req = kind_request(&srv, &owner, &[], kind).await;
            let status = srv.post("/v1/shares", Some(&owner.access), &req).await.0;
            assert_eq!(
                status,
                if enabled {
                    StatusCode::CREATED
                } else {
                    StatusCode::BAD_REQUEST
                }
            );
            let status = srv
                .get(&format!("/v1/shares?{flag}=true"), &owner.access)
                .await
                .0;
            assert_eq!(
                status,
                if enabled {
                    StatusCode::OK
                } else {
                    StatusCode::BAD_REQUEST
                }
            );
            assert_eq!(
                srv.get(&format!("/v1/shares?{flag}=false"), &owner.access)
                    .await
                    .0,
                StatusCode::OK
            );
        }
        // Baseline content stays available independently of either extension.
        for kind in [SharedItemKind::Host, SharedItemKind::Snippet] {
            create_kind(&srv, &owner, &[], kind).await;
        }
        assert_eq!(
            srv.get("/v1/meta", &owner.access).await.1["protocol_version"],
            "1.5"
        );
    }
}

#[tokio::test]
async fn duplicate_and_malformed_kind_flags_are_rejected() {
    let srv = server!(|c| {
        c.object_sharing_enabled = true;
        c.shared_groups_enabled = true;
        c.shared_secrets_enabled = true;
    });
    let owner = srv.new_account().await;
    for flag in ["include_groups", "include_secrets"] {
        for bad in ["", "1", "0", "yes", "TRUE", "null", "%20true", "true%20"] {
            let target = format!("/v1/shares?{flag}={bad}");
            assert_eq!(
                srv.get(&target, &owner.access).await.0,
                StatusCode::BAD_REQUEST
            );
        }
        for values in [("true", "true"), ("true", "false"), ("false", "false")] {
            let target = format!("/v1/shares?{flag}={}&{flag}={}", values.0, values.1);
            assert_eq!(
                srv.get(&target, &owner.access).await.0,
                StatusCode::BAD_REQUEST
            );
        }
    }
    // Distinct flags are independent, not interpreted as duplicate selectors.
    assert_eq!(
        srv.get(
            "/v1/shares?include_groups=true&include_secrets=true",
            &owner.access
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn mixed_kind_pagination_preserves_legacy_results_and_cursor_progress() {
    let srv = server!(|c| {
        c.object_sharing_enabled = true;
        c.shared_groups_enabled = true;
        c.shared_secrets_enabled = true;
    });
    let owner = srv.new_account().await;
    let stranger = srv.new_account().await;
    let kinds = [
        SharedItemKind::Group,
        SharedItemKind::Secret,
        SharedItemKind::Host,
        SharedItemKind::Group,
        SharedItemKind::Snippet,
        SharedItemKind::Secret,
        SharedItemKind::Host,
    ];
    let mut ids: Vec<_> = kinds.iter().map(|_| ShareId::new()).collect();
    ids.sort();
    for (&id, &kind) in ids.iter().zip(&kinds) {
        let mut req = kind_request(&srv, &owner, &[], kind).await;
        req.access.manifest.share_id = id;
        req.access = sign_manifest(&owner, req.access.manifest);
        req.revision = revision(&owner, &req.access.manifest, None);
        publish(&srv, &owner, &req).await;
    }
    for (flags, groups, secrets) in [
        ("", false, false),
        ("include_groups=false&include_secrets=false", false, false),
        ("include_groups=true", true, false),
        ("include_secrets=true", false, true),
        ("include_groups=true&include_secrets=true", true, true),
    ] {
        let expected: Vec<_> = ids
            .iter()
            .zip(&kinds)
            .filter_map(|(&id, kind)| match kind {
                SharedItemKind::Group if !groups => None,
                SharedItemKind::Secret if !secrets => None,
                _ => Some(id),
            })
            .collect();
        assert_eq!(paginated_ids(&srv, &owner, flags).await, expected);
    }
    assert!(
        paginated_ids(&srv, &stranger, "include_groups=true&include_secrets=true")
            .await
            .is_empty()
    );
    let baseline = service::list(&srv.state, &context(&owner), None, 100)
        .await
        .unwrap();
    assert!(baseline.items.iter().all(|item| matches!(
        item.access.manifest.kind,
        SharedItemKind::Host | SharedItemKind::Snippet
    )));
}

#[tokio::test]
async fn enabled_group_and_secret_follow_signed_lifecycle_with_immutable_kind() {
    let srv = server!(|c| {
        c.object_sharing_enabled = true;
        c.shared_groups_enabled = true;
        c.shared_secrets_enabled = true;
    });
    let owner = srv.new_account().await;
    let editor = srv.new_account().await;
    let reader = srv.new_account().await;
    for kind in [SharedItemKind::Group, SharedItemKind::Secret] {
        let old = create_kind(
            &srv,
            &owner,
            &[
                (&editor, SharingRole::Editor),
                (&reader, SharingRole::Reader),
            ],
            kind,
        )
        .await;
        let id = old.access.manifest.share_id;
        assert_eq!(srv.get(&path(id), &reader.access).await.0, StatusCode::OK);
        let edit = PutSharedRevisionRequest {
            revision: revision(&editor, &old.access.manifest, Some(&old.revision)),
        };
        let (status, body) = srv
            .post(
                &format!("{}/revisions", path(id)),
                Some(&editor.access),
                &edit,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let edited: SharedItemState = serde_json::from_value(body).unwrap();
        let forbidden = PutSharedRevisionRequest {
            revision: revision(&reader, &edited.access.manifest, Some(&edited.revision)),
        };
        assert_eq!(
            srv.post(
                &format!("{}/revisions", path(id)),
                Some(&reader.access),
                &forbidden
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );

        // Both flags are on: rejection must come from immutable context, not a disabled kind.
        let mut wrong_kind = rotation(&owner, &edited, edited.access.manifest.members.clone());
        wrong_kind.access.manifest.kind = if kind == SharedItemKind::Group {
            SharedItemKind::Secret
        } else {
            SharedItemKind::Group
        };
        wrong_kind.access = sign_manifest(&owner, wrong_kind.access.manifest);
        wrong_kind.revision = revision(&owner, &wrong_kind.access.manifest, Some(&edited.revision));
        assert_eq!(
            srv.post(
                &format!("{}/access", path(id)),
                Some(&owner.access),
                &wrong_kind
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (status, body) = srv.get(&path(id), &reader.access).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            serde_json::from_value::<SharedItemState>(body).unwrap() == edited,
            "failed kind replacement changed item state"
        );

        let rotate = rotation(
            &owner,
            &edited,
            vec![
                member(&owner, SharingRole::Editor),
                member(&reader, SharingRole::Reader),
            ],
        );
        let (status, body) = srv
            .post(
                &format!("{}/access", path(id)),
                Some(&owner.access),
                &rotate,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let current: SharedItemState = serde_json::from_value(body).unwrap();
        assert_eq!(current.access.manifest.kind, kind);
        assert_eq!(current.access.manifest.access_epoch, 2);
        assert_eq!(current.revision.signed.mutation.context.revision, 3);
        assert!(
            current.revision.body.as_ref().unwrap().ciphertext
                != edited.revision.body.as_ref().unwrap().ciphertext,
            "access rotation must replace ciphertext"
        );
        assert!(!current
            .revision
            .body
            .as_ref()
            .unwrap()
            .envelopes
            .iter()
            .any(|envelope| envelope.recipient_device_id == editor.device.id));
        assert_eq!(
            srv.get(&path(id), &editor.access).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            srv.get(&format!("{}/history", path(id)), &editor.access)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let (status, body) = srv
            .get(&format!("{}/history", path(id)), &reader.access)
            .await;
        assert_eq!(status, StatusCode::OK);
        let history: ShareHistoryPage = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(history.latest_revision, 3);
        assert_eq!(history.latest_manifest_revision, 2);
        assert_eq!(history.revisions.len(), 3);
        assert!(!body.to_string().contains("ciphertext"));
        assert!(!body.to_string().contains("envelopes"));
    }
}

async fn config_view(srv: &TestServer, groups: bool, secrets: bool) -> AppState {
    let mut config = srv.state.config.clone();
    config.shared_groups_enabled = groups;
    config.shared_secrets_enabled = secrets;
    config.event_bus = EventBusKind::Local;
    config.validate().unwrap();
    AppState::with_mailer(config, srv.state.db.clone(), srv.mailer.clone())
        .await
        .unwrap()
}

#[tokio::test]
async fn disabling_a_kind_hides_saved_data_and_rejects_writes_without_deleting_it() {
    let srv = server!(|c| {
        c.object_sharing_enabled = true;
        c.shared_groups_enabled = true;
        c.shared_secrets_enabled = true;
    });
    let owner = srv.new_account().await;
    let group = create_kind(&srv, &owner, &[], SharedItemKind::Group).await;
    let secret = create_kind(&srv, &owner, &[], SharedItemKind::Secret).await;
    let host = create_kind(&srv, &owner, &[], SharedItemKind::Host).await;
    for (groups, secrets) in [(false, true), (true, false), (false, false)] {
        let view = config_view(&srv, groups, secrets).await;
        let auth = context(&owner);
        let capabilities = service::capabilities(&view, &auth).await.unwrap();
        assert_eq!(capabilities.supports_groups, groups);
        assert_eq!(capabilities.supports_secrets, secrets);
        assert!(!capabilities.supports_owner_online_enrollment_v1);
        for (item, enabled) in [(&group, groups), (&secret, secrets)] {
            let id = item.access.manifest.share_id;
            if enabled {
                assert!(service::get(&view, &auth, id).await.is_ok());
                continue;
            }
            assert_eq!(
                service::get(&view, &auth, id).await.unwrap_err().code(),
                ErrorCode::NotFound
            );
            assert_eq!(
                service::history(&view, &auth, id, 0, 0, 100)
                    .await
                    .unwrap_err()
                    .code(),
                ErrorCode::NotFound
            );
            let put = PutSharedRevisionRequest {
                revision: revision(&owner, &item.access.manifest, Some(&item.revision)),
            };
            assert_eq!(
                service::put(&view, &auth, id, put)
                    .await
                    .unwrap_err()
                    .code(),
                ErrorCode::NotFound
            );
            let rotate = rotation(&owner, item, item.access.manifest.members.clone());
            assert_eq!(
                service::rotate(&view, &auth, id, rotate)
                    .await
                    .unwrap_err()
                    .code(),
                ErrorCode::BadRequest
            );
            assert_eq!(
                service::create(
                    &view,
                    &auth,
                    kind_request(&srv, &owner, &[], item.access.manifest.kind).await
                )
                .await
                .unwrap_err()
                .code(),
                ErrorCode::BadRequest
            );
        }
        let baseline = service::list(&view, &auth, None, 100).await.unwrap();
        assert_eq!(baseline.items.len(), 1);
        assert_eq!(
            baseline.items[0].access.manifest.share_id,
            host.access.manifest.share_id
        );
    }
    // Re-enabling the original view returns the exact stored signed states.
    for old in [&group, &secret] {
        let restored = service::get(&srv.state, &context(&owner), old.access.manifest.share_id)
            .await
            .unwrap();
        assert!(
            restored == *old,
            "gate toggling must preserve signed content and history"
        );
    }
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_items").await,
        3
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM shared_revision_headers")
            .await,
        3
    );
}

#[tokio::test]
async fn group_access_does_not_authorize_an_independent_child() {
    let srv = server!(|c| {
        c.object_sharing_enabled = true;
        c.shared_groups_enabled = true;
        c.shared_secrets_enabled = true;
    });
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    // Group references are opaque encrypted client data. The server must make
    // each child inaccessible until it receives its own explicit signed ACL.
    let child = create_kind(&srv, &owner, &[], SharedItemKind::Secret).await;
    let group = create_kind(
        &srv,
        &owner,
        &[(&reader, SharingRole::Reader)],
        SharedItemKind::Group,
    )
    .await;
    let child_id = child.access.manifest.share_id;
    assert_eq!(
        srv.get(&path(group.access.manifest.share_id), &reader.access)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        srv.get(&path(child_id), &reader.access).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.get(&format!("{}/history", path(child_id)), &reader.access)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        paginated_ids(&srv, &reader, "include_groups=true&include_secrets=true").await,
        vec![group.access.manifest.share_id]
    );
    let child_membership: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM shared_item_devices WHERE share_id=$1 AND user_id=$2",
    )
    .bind(Uuid::from(child_id))
    .bind(Uuid::from(reader.user_id))
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(child_membership, 0);
    let explicit = rotation(
        &owner,
        &child,
        vec![
            member(&owner, SharingRole::Editor),
            member(&reader, SharingRole::Reader),
        ],
    );
    assert_eq!(
        srv.post(
            &format!("{}/access", path(child_id)),
            Some(&owner.access),
            &explicit
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        srv.get(&path(child_id), &reader.access).await.0,
        StatusCode::OK
    );
    let untouched = service::get(&srv.state, &context(&owner), group.access.manifest.share_id)
        .await
        .unwrap();
    assert!(
        untouched == group,
        "child grant must not modify the Group ACL/content"
    );
}
