// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Owner-online enrollment authorization, atomicity and disclosure boundaries.
//! These server tests intentionally use opaque challenge ciphertext/digests;
//! successful X25519/AEAD verification remains a separate client requirement.
mod common;

use cc_protocol::{sharing::*, sharing_enrollment::*, ObjectId, ShareId};
use common::{enrollment as en, sharing::*, *};
use consolecrypt_server::{config::EventBusKind, AppState, Config};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

fn enabled(c: &mut Config) {
    c.object_sharing_enabled = true;
    c.sharing_owner_online_enrollment_enabled = true;
}

struct Fixture {
    owner: Session,
    anchor: Session,
    target: Session,
    old: SharedItemState,
    grant: SignedSharingOwnDevicesGrantState,
    submission: SubmitOwnDeviceRequest,
}
impl Fixture {
    async fn new(srv: &TestServer, role: SharingRole, mode: EnrollmentMode) -> Self {
        let owner = srv.new_account().await;
        let anchor = srv.new_account().await;
        let target = srv.new_device_session(&anchor, "enrollment target").await;
        let old = create(srv, &owner, &[(&anchor, role)]).await;
        let grant = en::grant(&owner, &anchor, &old, role, mode, 2);
        assert_eq!(en::publish_grant(srv, &owner, &grant).await, grant);
        let submission = en::submission(&target, &anchor, &grant, role);
        Self {
            owner,
            anchor,
            target,
            old,
            grant,
            submission,
        }
    }
    fn id(&self) -> ShareId {
        self.old.access.manifest.share_id
    }
    fn request_path(&self) -> String {
        en::request_path(self.id(), self.submission.request.request.request_id)
    }
    async fn submit(&self, srv: &TestServer) -> OwnDeviceRequestState {
        en::post(
            srv,
            &self.target,
            &en::requests_path(self.id()),
            &self.submission,
        )
        .await
    }
    async fn ready(&self, srv: &TestServer) -> AcceptOwnDeviceRequest {
        assert_eq!(
            self.submit(srv).await.status,
            OwnDeviceRequestStatus::Pending
        );
        let (challenge, response) =
            en::respond(srv, &self.owner, &self.target, &self.submission).await;
        en::acceptance(
            &self.owner,
            &self.target,
            &self.old,
            &self.grant,
            &self.submission,
            &challenge,
            &response,
        )
    }
    async fn unchanged(&self, srv: &TestServer) {
        let state: SharedItemState = en::get(srv, &self.owner, &path(self.id())).await;
        assert_eq!(
            state, self.old,
            "rejected enrollment must not modify item/ACL"
        );
        let grant: SignedSharingOwnDevicesGrantState = en::get(
            srv,
            &self.owner,
            &en::grant_path(self.id(), self.grant.grant.grant_id),
        )
        .await;
        assert_eq!(
            grant, self.grant,
            "rejected enrollment must not advance grant"
        );
    }
}
fn rejected(status: StatusCode) {
    assert!(
        status.is_client_error(),
        "expected safe rejection, got {status}"
    );
}
async fn reject_post(srv: &TestServer, caller: &Session, p: &str, value: &impl Serialize) {
    rejected(srv.post(p, Some(&caller.access), value).await.0);
}
async fn no_item_access(srv: &TestServer, caller: &Session, id: ShareId) {
    assert_eq!(
        srv.get(&path(id), &caller.access).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.get(&format!("{}/history", path(id)), &caller.access)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let page: ShareListPage = en::get(srv, caller, "/v1/shares").await;
    assert!(page
        .items
        .iter()
        .all(|item| item.access.manifest.share_id != id));
}
fn no_item_body(value: &Value, old: &SharedItemState) {
    let serialized = value.to_string();
    let body = serde_json::to_value(old.revision.body.as_ref().unwrap()).unwrap();
    assert!(!serialized.contains(body["ciphertext"].as_str().unwrap()));
    assert!(!serialized.contains("envelopes"));
    assert!(!serialized.contains("result_state"));
}

#[test]
fn enrollment_flag_defaults_off_and_requires_sharing_and_strict_proofs() {
    let mut c = Config::for_tests("postgres://localhost/unused");
    assert!(!c.sharing_owner_online_enrollment_enabled);
    c.sharing_owner_online_enrollment_enabled = true;
    assert!(c.validate().is_err());
    c.object_sharing_enabled = true;
    c.require_request_proof = false;
    assert!(c.validate().is_err());
    c.require_request_proof = true;
    assert!(c.validate().is_ok());
    assert!(!c.shared_groups_enabled && !c.shared_secrets_enabled);
}

#[tokio::test]
async fn reader_editor_manual_automatic_lifecycle_and_receipt_recovery() {
    let srv = server!(enabled);
    for (role, mode) in [
        (SharingRole::Reader, EnrollmentMode::Manual),
        (SharingRole::Reader, EnrollmentMode::Automatic),
        (SharingRole::Editor, EnrollmentMode::Manual),
        (SharingRole::Editor, EnrollmentMode::Automatic),
    ] {
        let f = Fixture::new(&srv, role, mode).await;
        let caps: SharingCapabilities = en::get(&srv, &f.owner, "/v1/shares/capabilities").await;
        assert!(caps.supports_owner_online_enrollment_v1);
        assert!(!caps.supports_groups && !caps.supports_secrets);
        no_item_access(&srv, &f.target, f.id()).await;
        let accept = f.ready(&srv).await;
        no_item_access(&srv, &f.target, f.id()).await;
        let state: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
        validate_request_state(&state).unwrap();
        assert_eq!(state.status, OwnDeviceRequestStatus::Responded);
        no_item_body(&serde_json::to_value(&state).unwrap(), &f.old);
        let result: OwnDeviceAcceptanceResult = en::post(
            &srv,
            &f.owner,
            &format!("{}/accept", f.request_path()),
            &accept,
        )
        .await;
        validate_acceptance_result(&result).unwrap();
        assert_eq!(result.acceptance, accept.acceptance);
        assert_eq!(
            result.consumed_grant_successor,
            accept.consumed_grant_successor
        );
        assert_eq!(result.state.access.manifest.access_epoch, 2);
        assert_eq!(result.state.revision.signed.mutation.context.revision, 2);
        assert_eq!(result.consumed_grant_successor.grant.admitted_count, 1);
        assert_eq!(
            result
                .consumed_grant_successor
                .grant
                .previous_grant_state_hash,
            en::grant_hash(&f.grant)
        );
        assert_eq!(
            result.state.access.manifest.members.len(),
            f.old.access.manifest.members.len() + 1
        );
        for original in &f.old.access.manifest.members {
            assert!(result.state.access.manifest.members.contains(original));
        }
        assert!(result
            .state
            .access
            .manifest
            .members
            .contains(&member(&f.target, role)));
        let read: SharedItemState = en::get(&srv, &f.target, &path(f.id())).await;
        assert_eq!(read, result.state);
        let recovered: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
        assert_eq!(recovered.status, OwnDeviceRequestStatus::Accepted);
        assert_eq!(recovered.acceptance, Some(result.acceptance.clone()));
        no_item_body(&serde_json::to_value(&recovered).unwrap(), &result.state);
        let history: OwnDevicesGrantHistoryPage = en::get(
            &srv,
            &f.target,
            &format!(
                "{}/history?after_revision=0&limit=1",
                en::grant_path(f.id(), f.grant.grant.grant_id)
            ),
        )
        .await;
        validate_grant_history_page(&history, &en::scope(&f.old), f.grant.grant.grant_id, 0)
            .unwrap();
        assert_eq!(history.states, vec![f.grant.clone()]);
        assert_eq!(history.latest_revision, 2);
        assert!(history.has_more);
        let history: OwnDevicesGrantHistoryPage = en::get(
            &srv,
            &f.target,
            &format!(
                "{}/history?after_revision=1&limit=1",
                en::grant_path(f.id(), f.grant.grant.grant_id)
            ),
        )
        .await;
        assert_eq!(
            history.states,
            vec![result.consumed_grant_successor.clone()]
        );
        assert!(!history.has_more);
        // The server may return an immutable receipt or reject a replay, but it
        // must never perform a second rotation or consume another admission.
        let (status, replay) = srv
            .post(
                &format!("{}/accept", f.request_path()),
                Some(&f.owner.access),
                &accept,
            )
            .await;
        if status.is_success() {
            let replay: OwnDeviceAcceptanceResult = serde_json::from_value(replay).unwrap();
            assert_eq!(replay, result);
        } else {
            rejected(status);
        }
        let current: SharedItemState = en::get(&srv, &f.owner, &path(f.id())).await;
        assert_eq!(current, result.state);
        let head: SignedSharingOwnDevicesGrantState = en::get(
            &srv,
            &f.owner,
            &en::grant_path(f.id(), f.grant.grant.grant_id),
        )
        .await;
        assert_eq!(head, result.consumed_grant_successor);
        let edit = PutSharedRevisionRequest {
            revision: revision(&f.target, &current.access.manifest, Some(&current.revision)),
        };
        let (status, _) = srv
            .post(
                &format!("{}/revisions", path(f.id())),
                Some(&f.target.access),
                &edit,
            )
            .await;
        if role == SharingRole::Reader {
            assert_eq!(status, StatusCode::FORBIDDEN);
        } else {
            assert_eq!(status, StatusCode::OK);
        }
        let stopped = en::revoked(&f.owner, &head);
        assert_eq!(en::publish_grant(&srv, &f.owner, &stopped).await, stopped);
        // Direct adoption survives grant disable; removing it requires an
        // ordinary explicit access rotation and fresh envelopes.
        assert_eq!(
            srv.get(&path(f.id()), &f.target.access).await.0,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn scoped_grant_reads_request_privacy_and_transport_possession() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let sibling = srv.new_device_session(&f.anchor, "unrelated sibling").await;
    let stranger = srv.new_account().await;
    let gpath = en::grant_path(f.id(), f.grant.grant.grant_id);
    let anchor_head: SignedSharingOwnDevicesGrantState = en::get(&srv, &f.anchor, &gpath).await;
    assert_eq!(anchor_head, f.grant);
    let anchor_page: OwnDevicesGrantPage = en::get(&srv, &f.anchor, &en::grants_path(f.id())).await;
    assert_eq!(anchor_page.items, vec![f.grant.clone()]);
    for caller in [&f.target, &sibling, &stranger] {
        assert_eq!(
            srv.get(&gpath, &caller.access).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            srv.get(&en::grants_path(f.id()), &caller.access).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            srv.get(&format!("{gpath}/history"), &caller.access).await.0,
            StatusCode::NOT_FOUND
        );
        no_item_access(&srv, caller, f.id()).await;
    }
    for caller in [&f.owner, &f.anchor, &sibling, &stranger] {
        reject_post(&srv, caller, &en::requests_path(f.id()), &f.submission).await;
    }
    // Possession of the bearer session and a copied signed payload alone is
    // insufficient: the HTTP request also needs the target's device proof.
    let raw = srv
        .http
        .post(srv.url(&en::requests_path(f.id())))
        .bearer_auth(&f.target.access)
        .json(&f.submission)
        .send()
        .await
        .unwrap();
    rejected(raw.status());
    let pending = f.submit(&srv).await;
    assert_eq!(pending.status, OwnDeviceRequestStatus::Pending);
    for caller in [&f.anchor, &sibling, &stranger] {
        assert_eq!(
            srv.get(&f.request_path(), &caller.access).await.0,
            StatusCode::NOT_FOUND
        );
    }
    for caller in [&f.anchor, &f.target, &sibling, &stranger] {
        assert_eq!(
            srv.get(&en::requests_path(f.id()), &caller.access).await.0,
            StatusCode::NOT_FOUND
        );
    }
    for caller in [&f.owner, &f.target] {
        let (_, body) = srv.get(&f.request_path(), &caller.access).await;
        no_item_body(&body, &f.old);
        let actual: OwnDeviceRequestState = serde_json::from_value(body).unwrap();
        assert_eq!(actual, pending);
    }
    let page: OwnDeviceRequestPage = en::get(&srv, &f.owner, &en::requests_path(f.id())).await;
    assert_eq!(page.items, vec![pending]);
    f.unchanged(&srv).await;
}

#[tokio::test]
async fn request_target_reads_only_its_associated_public_grant_transcript() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let sibling = srv
        .new_device_session(&f.anchor, "other request target")
        .await;
    let stranger = srv.new_account().await;
    let gpath = en::grant_path(f.id(), f.grant.grant.grant_id);
    f.submit(&srv).await;
    let head: SignedSharingOwnDevicesGrantState = en::get(&srv, &f.target, &gpath).await;
    assert_eq!(head, f.grant);
    let history: OwnDevicesGrantHistoryPage =
        en::get(&srv, &f.target, &format!("{gpath}/history")).await;
    assert_eq!(history.states, vec![f.grant.clone()]);
    assert_eq!(history.latest_revision, 1);
    assert!(!history.has_more);
    for p in [&gpath, &format!("{gpath}/history")] {
        let (status, body) = srv.get(p, &f.target.access).await;
        assert_eq!(status, StatusCode::OK);
        no_item_body(&body, &f.old);
        for caller in [&sibling, &stranger] {
            assert_eq!(srv.get(p, &caller.access).await.0, StatusCode::NOT_FOUND);
        }
        let raw = srv
            .http
            .get(srv.url(p))
            .bearer_auth(&f.target.access)
            .send()
            .await
            .unwrap();
        assert_eq!(raw.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    let other_grant = en::grant(
        &f.owner,
        &f.anchor,
        &f.old,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        2,
    );
    en::publish_grant(&srv, &f.owner, &other_grant).await;
    let other_request = en::submission(&sibling, &f.anchor, &other_grant, SharingRole::Reader);
    let _: OwnDeviceRequestState =
        en::post(&srv, &sibling, &en::requests_path(f.id()), &other_request).await;
    // Sharing an account/anchor/item does not authorize another request's grant.
    let other = en::grant_path(f.id(), other_grant.grant.grant_id);
    for p in [
        other.clone(),
        format!("{other}/history"),
        format!("{other}/history?after_revision=999"),
        en::grants_path(f.id()),
    ] {
        assert_eq!(srv.get(&p, &f.target.access).await.0, StatusCode::NOT_FOUND);
    }
    let other_item = create(&srv, &f.owner, &[(&f.anchor, SharingRole::Reader)]).await;
    let wrong_scope = en::grant_path(other_item.access.manifest.share_id, f.grant.grant.grant_id);
    assert_eq!(
        srv.get(&wrong_scope, &f.target.access).await.0,
        StatusCode::NOT_FOUND
    );
    no_item_access(&srv, &f.target, f.id()).await;
    let revoked = PublishOwnDevicesGrantRequest {
        grant: en::revoked(&f.owner, &f.grant),
    };
    assert_eq!(
        srv.post(&en::grants_path(f.id()), Some(&f.target.access), &revoked)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    f.unchanged(&srv).await;
}

#[tokio::test]
async fn accepted_target_recovers_consumed_and_terminal_history_after_acl_removal() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let accept = f.ready(&srv).await;
    let accepted: OwnDeviceAcceptanceResult = en::post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &accept,
    )
    .await;
    let gpath = en::grant_path(f.id(), f.grant.grant.grant_id);
    let head: SignedSharingOwnDevicesGrantState = en::get(&srv, &f.target, &gpath).await;
    assert_eq!(
        en::grant_hash(&head),
        accepted.acceptance.acceptance.consumed_grant_successor_hash
    );
    let revoked = en::revoked(&f.owner, &head);
    // Even an admitted target with an owner-signed body cannot perform owner ops.
    assert_eq!(
        srv.post(
            &en::grants_path(f.id()),
            Some(&f.target.access),
            &PublishOwnDevicesGrantRequest {
                grant: revoked.clone()
            }
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.post(
            &format!("{}/accept", f.request_path()),
            Some(&f.target.access),
            &accept
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let grants: OwnDevicesGrantPage = en::get(&srv, &f.target, &en::grants_path(f.id())).await;
    assert!(grants.items.is_empty());
    let unrelated = en::grant(
        &f.owner,
        &f.anchor,
        &accepted.state,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        2,
    );
    en::publish_grant(&srv, &f.owner, &unrelated).await;
    let other_path = en::grant_path(f.id(), unrelated.grant.grant_id);
    for p in [other_path.clone(), format!("{other_path}/history")] {
        assert_eq!(srv.get(&p, &f.target.access).await.0, StatusCode::NOT_FOUND);
    }
    let vault = srv.create_vault(&f.owner).await;
    assert_eq!(
        srv.get(&format!("/v1/vaults/{}", vault.id), &f.target.access)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    en::publish_grant(&srv, &f.owner, &revoked).await;
    let remove = rotation(
        &f.owner,
        &accepted.state,
        vec![member(&f.owner, SharingRole::Editor)],
    );
    let _: SharedItemState =
        en::post(&srv, &f.owner, &format!("{}/access", path(f.id())), &remove).await;
    no_item_access(&srv, &f.target, f.id()).await;
    // Recovery does not depend on the continued existence of the original anchor.
    sqlx::query("DELETE FROM devices WHERE id=$1")
        .bind(Uuid::from(f.anchor.device.id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    let terminal: SignedSharingOwnDevicesGrantState = en::get(&srv, &f.target, &gpath).await;
    assert_eq!(terminal, revoked);
    let history: OwnDevicesGrantHistoryPage =
        en::get(&srv, &f.target, &format!("{gpath}/history")).await;
    validate_grant_history_page(&history, &en::scope(&f.old), f.grant.grant.grant_id, 0).unwrap();
    assert_eq!(history.states, vec![f.grant.clone(), head, revoked]);
    assert_eq!(history.latest_revision, 3);
    assert!(!history.has_more);
    let receipt: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
    assert_eq!(receipt.acceptance, Some(accepted.acceptance));
    assert_eq!(
        srv.get(&en::grants_path(f.id()), &f.target.access).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn target_grant_reads_require_both_current_registered_keys_before_and_after_acceptance() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let accept = f.ready(&srv).await;
    let gpath = en::grant_path(f.id(), f.grant.grant.grant_id);
    for accepted in [false, true] {
        if accepted {
            let _: OwnDeviceAcceptanceResult = en::post(
                &srv,
                &f.owner,
                &format!("{}/accept", f.request_path()),
                &accept,
            )
            .await;
        }
        for (encryption_changed, signing_changed) in [(true, false), (false, true), (true, true)] {
            let mut changed = TestDevice::new("replacement registration");
            changed.id = f.target.device.id;
            if !encryption_changed {
                changed.encryption_public_key = f.target.device.encryption_public_key;
            }
            if !signing_changed {
                changed.signing = f.target.device.signing.clone();
            }
            sqlx::query(
                "UPDATE devices SET encryption_public_key=$2, signing_public_key=$3 WHERE id=$1",
            )
            .bind(Uuid::from(changed.id))
            .bind(changed.encryption_public_key.as_slice())
            .bind(changed.signing_public_key().as_slice())
            .execute(&srv.state.db)
            .await
            .unwrap();
            srv.register_signer(&f.target.access, &changed);
            // Prove the transport is authenticated with the replacement key;
            // the 404 must come from the stored target binding, not bad proof.
            assert_eq!(
                srv.get("/v1/auth/me", &f.target.access).await.0,
                StatusCode::OK
            );
            for p in [&gpath, &format!("{gpath}/history")] {
                let (status, body) = srv.get(p, &f.target.access).await;
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(body["code"], "not_found");
            }
            sqlx::query(
                "UPDATE devices SET encryption_public_key=$2, signing_public_key=$3 WHERE id=$1",
            )
            .bind(Uuid::from(f.target.device.id))
            .bind(f.target.device.encryption_public_key.as_slice())
            .bind(f.target.device.signing_public_key().as_slice())
            .execute(&srv.state.db)
            .await
            .unwrap();
            srv.register_signer(&f.target.access, &f.target.device);
            assert_eq!(srv.get(&gpath, &f.target.access).await.0, StatusCode::OK);
        }
    }
}

#[tokio::test]
async fn request_rejects_wrong_context_keys_role_hash_domain_and_endorsement() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let stranger = srv.new_account().await;
    let mut cases = Vec::new();
    for case in 0..12 {
        let mut bad = f.submission.clone();
        let mut request = bad.request.request.clone();
        match case {
            0 => request.scope.server_instance_id = Uuid::new_v4(),
            1 => request.scope.share_id = ShareId::new(),
            2 => request.scope.item_id = ObjectId::new(),
            3 => request.scope.kind = SharedItemKind::Snippet,
            4 => request.target.user_id = stranger.user_id,
            5 => request.target.device_id = f.anchor.device.id,
            6 => request.target.encryption_public_key = random::<32>().to_vec().into(),
            7 => request.target.signing_public_key = random::<32>().to_vec().into(),
            8 => request.requested_role = SharingRole::Editor,
            9 => request.grant_state_hash = random::<32>().to_vec().into(),
            10 => request.access_manifest_hash = random::<32>().to_vec().into(),
            _ => request.access_epoch += 1,
        }
        bad.request = en::sign_request(&f.target, request);
        bad.endorsement = en::endorsement(&f.anchor, &bad.request);
        cases.push(bad);
    }
    let mut bad = f.submission.clone();
    bad.request.signature = random::<64>().to_vec().into();
    bad.endorsement = en::endorsement(&f.anchor, &bad.request);
    cases.push(bad);
    let mut bad = f.submission.clone();
    bad.request.signature = en::signature(
        &f.target,
        &enrollment_pairing_message(&random::<32>()).unwrap(),
    );
    bad.endorsement = en::endorsement(&f.anchor, &bad.request);
    cases.push(bad);
    let mut bad = f.submission.clone();
    bad.endorsement.signature = random::<64>().to_vec().into();
    cases.push(bad);
    let mut bad = f.submission.clone();
    bad.endorsement = en::sign_endorsement(&stranger, bad.endorsement.endorsement);
    cases.push(bad);
    let mut bad = f.submission.clone();
    bad.endorsement.endorsement.request_hash = random::<32>().to_vec().into();
    bad.endorsement = en::sign_endorsement(&f.anchor, bad.endorsement.endorsement);
    cases.push(bad);
    let mut bad = f.submission.clone();
    bad.endorsement.endorsement.anchor_device_id = stranger.device.id;
    bad.endorsement = en::sign_endorsement(&f.anchor, bad.endorsement.endorsement);
    cases.push(bad);
    for (index, bad) in cases.into_iter().enumerate() {
        let (status, _) = srv
            .post(&en::requests_path(f.id()), Some(&f.target.access), &bad)
            .await;
        assert!(
            status.is_client_error(),
            "request rejection case {index}: {status}"
        );
    }
    let page: OwnDeviceRequestPage = en::get(&srv, &f.owner, &en::requests_path(f.id())).await;
    assert!(page.items.is_empty());
    f.unchanged(&srv).await;
    // All negative probes leave the original request usable.
    assert_eq!(f.submit(&srv).await.status, OwnDeviceRequestStatus::Pending);
}

#[tokio::test]
async fn grant_genesis_owner_signature_bindings_and_frozen_terminal_chain() {
    let srv = server!(enabled);
    let owner = srv.new_account().await;
    let anchor = srv.new_account().await;
    let other = srv.new_account().await;
    let old = create(&srv, &owner, &[(&anchor, SharingRole::Reader)]).await;
    let original = en::grant(
        &owner,
        &anchor,
        &old,
        SharingRole::Reader,
        EnrollmentMode::Automatic,
        2,
    );
    let p = en::grants_path(old.access.manifest.share_id);
    let mut cases = Vec::new();
    for case in 0..7 {
        let mut value = original.grant.clone();
        match case {
            0 => value.owner_device_id = other.device.id,
            1 => value.anchor = en::binding(&other),
            2 => value.anchor.encryption_public_key = random::<32>().to_vec().into(),
            3 => value.role_ceiling = SharingRole::Editor,
            4 => value.access_manifest_hash = random::<32>().to_vec().into(),
            5 => value.access_epoch += 1,
            _ => value.scope.server_instance_id = Uuid::new_v4(),
        }
        cases.push(en::sign_grant(&owner, value));
    }
    let mut bad = original.clone();
    bad.signature = random::<64>().to_vec().into();
    cases.push(bad);
    let mut bad = original.clone();
    bad.signature = en::signature(
        &owner,
        &sharing_manifest_message(&old.access.manifest).unwrap(),
    );
    cases.push(bad);
    for bad in cases {
        reject_post(
            &srv,
            &owner,
            &p,
            &PublishOwnDevicesGrantRequest { grant: bad },
        )
        .await;
    }
    reject_post(
        &srv,
        &anchor,
        &p,
        &PublishOwnDevicesGrantRequest {
            grant: original.clone(),
        },
    )
    .await;
    let page: OwnDevicesGrantPage = en::get(&srv, &owner, &p).await;
    assert!(page.items.is_empty());
    assert_eq!(en::publish_grant(&srv, &owner, &original).await, original);
    let active_successor = en::successor(&owner, &original, &old.access.manifest, 0);
    reject_post(
        &srv,
        &owner,
        &p,
        &PublishOwnDevicesGrantRequest {
            grant: active_successor,
        },
    )
    .await;
    let stop = en::revoked(&owner, &original);
    for case in 0..5 {
        let mut bad = stop.grant.clone();
        match case {
            0 => bad.expires_at += 1,
            1 => bad.mode = EnrollmentMode::Manual,
            2 => bad.max_admissions += 1,
            3 => bad.anchor = en::binding(&other),
            _ => bad.admitted_count += 1,
        }
        reject_post(
            &srv,
            &owner,
            &p,
            &PublishOwnDevicesGrantRequest {
                grant: en::sign_grant(&owner, bad),
            },
        )
        .await;
    }
    assert_eq!(en::publish_grant(&srv, &owner, &stop).await, stop);
    let mut revival = stop.grant.clone();
    revival.grant_revision += 1;
    revival.previous_grant_state_hash = en::grant_hash(&stop);
    revival.status = EnrollmentGrantStatus::Active;
    reject_post(
        &srv,
        &owner,
        &p,
        &PublishOwnDevicesGrantRequest {
            grant: en::sign_grant(&owner, revival),
        },
    )
    .await;
    reject_post(
        &srv,
        &owner,
        &p,
        &PublishOwnDevicesGrantRequest { grant: original },
    )
    .await;
    let head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &owner,
        &en::grant_path(old.access.manifest.share_id, stop.grant.grant_id),
    )
    .await;
    assert_eq!(head, stop);
}

#[tokio::test]
async fn challenge_generation_and_exact_response_signer_hashes_are_enforced() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    f.submit(&srv).await;
    let p = f.request_path();
    let first = en::challenge(&f.owner, &f.submission, 1);
    let mut bad = first.clone();
    bad.challenge.request_hash = random::<32>().to_vec().into();
    bad = en::sign_challenge(&f.owner, bad.challenge);
    reject_post(
        &srv,
        &f.owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest { challenge: bad },
    )
    .await;
    let mut bad = first.clone();
    bad.challenge.anchor_endorsement_hash = random::<32>().to_vec().into();
    bad = en::sign_challenge(&f.owner, bad.challenge);
    reject_post(
        &srv,
        &f.owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest { challenge: bad },
    )
    .await;
    let mut bad = first.clone();
    bad.signature = random::<64>().to_vec().into();
    reject_post(
        &srv,
        &f.owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest { challenge: bad },
    )
    .await;
    for caller in [&f.anchor, &f.target] {
        reject_post(
            &srv,
            caller,
            &format!("{p}/challenge"),
            &PublishOwnDeviceChallengeRequest {
                challenge: first.clone(),
            },
        )
        .await;
    }
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &f.owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest {
            challenge: first.clone(),
        },
    )
    .await;
    let stale = en::response(&f.target, &first);
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &f.target,
        &format!("{p}/response"),
        &SubmitOwnDeviceChallengeResponseRequest {
            response: stale.clone(),
        },
    )
    .await;
    let second = en::challenge(&f.owner, &f.submission, 2);
    let updated: OwnDeviceRequestState = en::post(
        &srv,
        &f.owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest {
            challenge: second.clone(),
        },
    )
    .await;
    assert_eq!(updated.status, OwnDeviceRequestStatus::Challenged);
    assert!(
        updated.response.is_none(),
        "replacement must invalidate the earlier response"
    );
    reject_post(
        &srv,
        &f.target,
        &format!("{p}/response"),
        &SubmitOwnDeviceChallengeResponseRequest {
            response: stale.clone(),
        },
    )
    .await;
    let stale_accept = en::acceptance(
        &f.owner,
        &f.target,
        &f.old,
        &f.grant,
        &f.submission,
        &first,
        &stale,
    );
    reject_post(&srv, &f.owner, &format!("{p}/accept"), &stale_accept).await;
    reject_post(
        &srv,
        &f.owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest { challenge: first },
    )
    .await;
    let response = en::response(&f.target, &second);
    let mut cases = Vec::new();
    let mut bad = response.clone();
    bad.response.request_hash = random::<32>().to_vec().into();
    cases.push(en::sign_response(&f.target, bad.response));
    let mut bad = response.clone();
    bad.response.challenge_hash = random::<32>().to_vec().into();
    cases.push(en::sign_response(&f.target, bad.response));
    cases.push(en::sign_response(&f.anchor, response.response.clone()));
    let mut bad = response.clone();
    bad.signature = random::<64>().to_vec().into();
    cases.push(bad);
    for bad in cases {
        reject_post(
            &srv,
            &f.target,
            &format!("{p}/response"),
            &SubmitOwnDeviceChallengeResponseRequest { response: bad },
        )
        .await;
    }
    for caller in [&f.owner, &f.anchor] {
        reject_post(
            &srv,
            caller,
            &format!("{p}/response"),
            &SubmitOwnDeviceChallengeResponseRequest {
                response: response.clone(),
            },
        )
        .await;
    }
    f.unchanged(&srv).await;
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &f.target,
        &format!("{p}/response"),
        &SubmitOwnDeviceChallengeResponseRequest {
            response: response.clone(),
        },
    )
    .await;
    let accepted: OwnDeviceAcceptanceResult = en::post(
        &srv,
        &f.owner,
        &format!("{p}/accept"),
        &en::acceptance(
            &f.owner,
            &f.target,
            &f.old,
            &f.grant,
            &f.submission,
            &second,
            &response,
        ),
    )
    .await;
    assert_eq!(
        accepted.acceptance.acceptance.challenge_hash,
        en::challenge_hash(&second)
    );
}

#[tokio::test]
async fn acceptance_requires_exact_acl_delta_transcript_signatures_and_successor() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let extra = srv.new_account().await;
    let original = f.ready(&srv).await;
    let mut cases = Vec::new();
    // These carry fresh, otherwise valid v1 owner signatures and exact body
    // envelope coverage. Rejection must come from the enrollment ACL rule.
    for case in 0..4 {
        let mut bad = original.clone();
        let mut members = bad.rotation.access.manifest.members.clone();
        match case {
            0 => members.push(member(&extra, SharingRole::Reader)),
            1 => members.retain(|m| m.device_id != f.anchor.device.id),
            2 => {
                members
                    .iter_mut()
                    .find(|m| m.device_id == f.anchor.device.id)
                    .unwrap()
                    .role = SharingRole::Editor
            }
            _ => {
                members
                    .iter_mut()
                    .find(|m| m.device_id == f.target.device.id)
                    .unwrap()
                    .role = SharingRole::Editor
            }
        }
        bad.rotation = rotation(&f.owner, &f.old, members);
        bad.consumed_grant_successor =
            en::successor(&f.owner, &f.grant, &bad.rotation.access.manifest, 1);
        en::resign_acceptance(&f.owner, &mut bad);
        cases.push(bad);
    }
    for field in 0..8 {
        let mut bad = original.clone();
        let a = &mut bad.acceptance.acceptance;
        let target = match field {
            0 => &mut a.request_hash,
            1 => &mut a.anchor_endorsement_hash,
            2 => &mut a.challenge_hash,
            3 => &mut a.response_hash,
            4 => &mut a.consumed_grant_state_hash,
            5 => &mut a.result_access_manifest_hash,
            6 => &mut a.result_revision_hash,
            _ => &mut a.consumed_grant_successor_hash,
        };
        *target = random::<32>().to_vec().into();
        bad.acceptance = en::sign_acceptance(&f.owner, bad.acceptance.acceptance);
        cases.push(bad);
    }
    for case in 0..5 {
        let mut bad = original.clone();
        match case {
            0 => bad.acceptance.signature = random::<64>().to_vec().into(),
            1 => bad.acceptance = en::sign_acceptance(&f.anchor, bad.acceptance.acceptance),
            2 => {
                bad.acceptance.signature = en::signature(
                    &f.owner,
                    &sharing_manifest_message(&bad.rotation.access.manifest).unwrap(),
                )
            }
            3 => bad.consumed_grant_successor.signature = random::<64>().to_vec().into(),
            _ => bad.rotation.revision.signed.signature = random::<64>().to_vec().into(),
        }
        cases.push(bad);
    }
    for case in 0..5 {
        let mut bad = original.clone();
        let next = &mut bad.consumed_grant_successor.grant;
        match case {
            0 => next.expires_at += 1,
            1 => next.max_admissions += 1,
            2 => next.admitted_count = 0,
            3 => next.mode = EnrollmentMode::Automatic,
            _ => next.previous_grant_state_hash = random::<32>().to_vec().into(),
        }
        bad.consumed_grant_successor = en::sign_grant(&f.owner, next.clone());
        en::resign_acceptance(&f.owner, &mut bad);
        cases.push(bad);
    }
    for (index, bad) in cases.into_iter().enumerate() {
        let (status, _) = srv
            .post(
                &format!("{}/accept", f.request_path()),
                Some(&f.owner.access),
                &bad,
            )
            .await;
        assert!(
            status.is_client_error(),
            "acceptance rejection case {index}: {status}"
        );
        f.unchanged(&srv).await;
        let request: OwnDeviceRequestState = en::get(&srv, &f.owner, &f.request_path()).await;
        assert_eq!(request.status, OwnDeviceRequestStatus::Responded);
        assert!(request.acceptance.is_none());
    }
    for caller in [&f.anchor, &f.target] {
        reject_post(
            &srv,
            caller,
            &format!("{}/accept", f.request_path()),
            &original,
        )
        .await;
    }
    let accepted: OwnDeviceAcceptanceResult = en::post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &original,
    )
    .await;
    assert_eq!(accepted.acceptance, original.acceptance);
}

#[tokio::test]
async fn stale_access_grants_cannot_be_rebound_but_owner_can_revoke() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Automatic).await;
    let accept = f.ready(&srv).await;
    let rotate = rotation(&f.owner, &f.old, f.old.access.manifest.members.clone());
    let current: SharedItemState =
        en::post(&srv, &f.owner, &format!("{}/access", path(f.id())), &rotate).await;
    reject_post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &accept,
    )
    .await;
    let fresh_target = srv.new_device_session(&f.anchor, "second target").await;
    let stale = en::submission(&fresh_target, &f.anchor, &f.grant, SharingRole::Reader);
    reject_post(&srv, &fresh_target, &en::requests_path(f.id()), &stale).await;
    let rebound = en::successor(&f.owner, &f.grant, &current.access.manifest, 0);
    reject_post(
        &srv,
        &f.owner,
        &en::grants_path(f.id()),
        &PublishOwnDevicesGrantRequest { grant: rebound },
    )
    .await;
    let head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), f.grant.grant.grant_id),
    )
    .await;
    assert_eq!(head, f.grant);
    let revoked = en::revoked(&f.owner, &head);
    assert_eq!(en::publish_grant(&srv, &f.owner, &revoked).await, revoked);
    no_item_access(&srv, &f.target, f.id()).await;
}

#[tokio::test]
async fn concurrent_acceptance_and_content_cas_do_not_partially_consume() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Editor, EnrollmentMode::Manual).await;
    let accept = f.ready(&srv).await;
    let edit = PutSharedRevisionRequest {
        revision: revision(&f.anchor, &f.old.access.manifest, Some(&f.old.revision)),
    };
    let edited: SharedItemState = en::post(
        &srv,
        &f.anchor,
        &format!("{}/revisions", path(f.id())),
        &edit,
    )
    .await;
    reject_post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &accept,
    )
    .await;
    let head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), f.grant.grant.grant_id),
    )
    .await;
    assert_eq!(head, f.grant);
    let pending: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
    assert_eq!(pending.status, OwnDeviceRequestStatus::Responded);
    let retried = en::acceptance(
        &f.owner,
        &f.target,
        &edited,
        &f.grant,
        &f.submission,
        pending.challenge.as_ref().unwrap(),
        pending.response.as_ref().unwrap(),
    );
    let p = format!("{}/accept", f.request_path());
    let (a, b) = tokio::join!(
        srv.post(&p, Some(&f.owner.access), &retried),
        srv.post(&p, Some(&f.owner.access), &retried)
    );
    assert!(a.0.is_success() || b.0.is_success());
    for result in [a, b] {
        if !result.0.is_success() {
            rejected(result.0);
        }
    }
    let final_state: SharedItemState = en::get(&srv, &f.owner, &path(f.id())).await;
    assert_eq!(final_state.revision.signed.mutation.context.revision, 3);
    assert_eq!(final_state.access.manifest.access_epoch, 2);
    let head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), f.grant.grant.grant_id),
    )
    .await;
    assert_eq!(head.grant.admitted_count, 1);
    assert_eq!(head.grant.grant_revision, 2);
}

#[tokio::test]
async fn revoked_anchor_or_target_blocks_acceptance_but_owner_can_terminally_revoke() {
    let srv = server!(enabled);
    for revoke_anchor in [true, false] {
        let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Automatic).await;
        let accept = f.ready(&srv).await;
        let revoked = if revoke_anchor { &f.anchor } else { &f.target };
        assert_eq!(
            srv.post(
                &format!("/v1/devices/{}/revoke", revoked.device.id),
                Some(&revoked.access),
                &json!({})
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        reject_post(
            &srv,
            &f.owner,
            &format!("{}/accept", f.request_path()),
            &accept,
        )
        .await;
        f.unchanged(&srv).await;
        let stopped = en::revoked(&f.owner, &f.grant);
        assert_eq!(en::publish_grant(&srv, &f.owner, &stopped).await, stopped);
    }
}

#[tokio::test]
async fn grant_request_and_challenge_expiry_prevent_late_acceptance_allow_revoke() {
    let srv = server!(enabled);
    let owner = srv.new_account().await;
    let anchor = srv.new_account().await;
    let target = srv.new_device_session(&anchor, "expiring target").await;
    let old = create(&srv, &owner, &[(&anchor, SharingRole::Reader)]).await;
    let mut grant = en::grant(
        &owner,
        &anchor,
        &old,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        1,
    );
    grant.grant.expires_at = now_unix() + 3;
    grant = en::sign_grant(&owner, grant.grant);
    en::publish_grant(&srv, &owner, &grant).await;
    let request = en::submission(&target, &anchor, &grant, SharingRole::Reader);
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &target,
        &en::requests_path(old.access.manifest.share_id),
        &request,
    )
    .await;
    let (challenge, response) = en::respond(&srv, &owner, &target, &request).await;
    let accept = en::acceptance(
        &owner, &target, &old, &grant, &request, &challenge, &response,
    );
    let wait = (grant.grant.expires_at - now_unix()).max(0) as u64 + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    reject_post(
        &srv,
        &owner,
        &format!(
            "{}/accept",
            en::request_path(
                old.access.manifest.share_id,
                request.request.request.request_id
            )
        ),
        &accept,
    )
    .await;
    let current: SharedItemState = en::get(&srv, &owner, &path(old.access.manifest.share_id)).await;
    assert_eq!(current, old);
    let stopped = en::revoked(&owner, &grant);
    assert_eq!(en::publish_grant(&srv, &owner, &stopped).await, stopped);
    no_item_access(&srv, &target, old.access.manifest.share_id).await;
    // Expiry ends admission authority, not exact-target proof recovery.
    let p = en::grant_path(old.access.manifest.share_id, grant.grant.grant_id);
    let head: SignedSharingOwnDevicesGrantState = en::get(&srv, &target, &p).await;
    assert_eq!(head, stopped);
    let history: OwnDevicesGrantHistoryPage = en::get(&srv, &target, &format!("{p}/history")).await;
    assert_eq!(history.states, vec![grant, stopped]);
}

async fn router_view(srv: &TestServer, configure: impl FnOnce(&mut Config)) -> axum::Router {
    let mut config = srv.state.config.clone();
    config.event_bus = EventBusKind::Local;
    configure(&mut config);
    config.validate().unwrap();
    let state = AppState::with_mailer(config, srv.state.db.clone(), srv.mailer.clone())
        .await
        .unwrap();
    consolecrypt_server::build_router(state)
}
async fn view_call(
    srv: &TestServer,
    router: &axum::Router,
    caller: &Session,
    method: Method,
    p: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let bytes = body
        .as_ref()
        .map(|v| serde_json::to_vec(v).unwrap())
        .unwrap_or_default();
    let proof = srv
        .proof_for(&caller.access, method.as_str(), p, &bytes)
        .unwrap();
    let mut request = Request::builder()
        .method(method)
        .uri(p)
        .header("authorization", format!("Bearer {}", caller.access))
        .header(cc_protocol::version::HEADER_DEVICE_PROOF, proof);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request.body(Body::from(bytes)).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn disabling_enrollment_or_kind_preserves_owner_revoke_and_chain_recovery_only() {
    let srv = server!(|c| {
        enabled(c);
        c.shared_groups_enabled = true;
        c.shared_secrets_enabled = true;
    });
    for kind in [
        SharedItemKind::Host,
        SharedItemKind::Group,
        SharedItemKind::Secret,
    ] {
        let owner = srv.new_account().await;
        let anchor = srv.new_account().await;
        let target = srv.new_device_session(&anchor, "gated target").await;
        let mut create = request(&srv, &owner, &[(&anchor, SharingRole::Reader)]).await;
        create.access.manifest.kind = kind;
        create.access = sign_manifest(&owner, create.access.manifest);
        create.revision = revision(&owner, &create.access.manifest, None);
        let old: SharedItemState = en::post(&srv, &owner, "/v1/shares", &create).await;
        let grant = en::grant(
            &owner,
            &anchor,
            &old,
            SharingRole::Reader,
            EnrollmentMode::Manual,
            2,
        );
        en::publish_grant(&srv, &owner, &grant).await;
        let submission = en::submission(&target, &anchor, &grant, SharingRole::Reader);
        let f = Fixture {
            owner,
            anchor,
            target,
            old,
            grant,
            submission,
        };
        let accept = f.ready(&srv).await;
        let view = router_view(&srv, |c| match kind {
            SharedItemKind::Host => c.sharing_owner_online_enrollment_enabled = false,
            SharedItemKind::Group => c.shared_groups_enabled = false,
            SharedItemKind::Secret => c.shared_secrets_enabled = false,
            _ => unreachable!(),
        })
        .await;
        let (_, caps) = view_call(
            &srv,
            &view,
            &f.owner,
            Method::GET,
            "/v1/shares/capabilities",
            None,
        )
        .await;
        assert_eq!(
            caps["supports_owner_online_enrollment_v1"],
            kind != SharedItemKind::Host
        );
        let gpath = en::grant_path(f.id(), f.grant.grant.grant_id);
        for p in [
            en::grants_path(f.id()),
            gpath.clone(),
            format!("{gpath}/history"),
        ] {
            let (status, value) = view_call(&srv, &view, &f.owner, Method::GET, &p, None).await;
            assert_eq!(status, StatusCode::OK);
            no_item_body(&value, &f.old);
            for caller in [&f.anchor, &f.target] {
                assert_eq!(
                    view_call(&srv, &view, caller, Method::GET, &p, None)
                        .await
                        .0,
                    StatusCode::NOT_FOUND
                );
            }
        }
        for caller in [&f.owner, &f.target] {
            assert_eq!(
                view_call(&srv, &view, caller, Method::GET, &f.request_path(), None)
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            view_call(
                &srv,
                &view,
                &f.owner,
                Method::GET,
                &en::requests_path(f.id()),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let fresh = en::grant(
            &f.owner,
            &f.anchor,
            &f.old,
            SharingRole::Reader,
            EnrollmentMode::Manual,
            1,
        );
        rejected(
            view_call(
                &srv,
                &view,
                &f.owner,
                Method::POST,
                &en::grants_path(f.id()),
                Some(serde_json::to_value(PublishOwnDevicesGrantRequest { grant: fresh }).unwrap()),
            )
            .await
            .0,
        );
        rejected(
            view_call(
                &srv,
                &view,
                &f.target,
                Method::POST,
                &en::requests_path(f.id()),
                Some(serde_json::to_value(&f.submission).unwrap()),
            )
            .await
            .0,
        );
        let challenge = en::challenge(&f.owner, &f.submission, 2);
        rejected(
            view_call(
                &srv,
                &view,
                &f.owner,
                Method::POST,
                &format!("{}/challenge", f.request_path()),
                Some(
                    serde_json::to_value(PublishOwnDeviceChallengeRequest {
                        challenge: challenge.clone(),
                    })
                    .unwrap(),
                ),
            )
            .await
            .0,
        );
        rejected(
            view_call(
                &srv,
                &view,
                &f.target,
                Method::POST,
                &format!("{}/response", f.request_path()),
                Some(
                    serde_json::to_value(SubmitOwnDeviceChallengeResponseRequest {
                        response: en::response(&f.target, &challenge),
                    })
                    .unwrap(),
                ),
            )
            .await
            .0,
        );
        rejected(
            view_call(
                &srv,
                &view,
                &f.owner,
                Method::POST,
                &format!("{}/accept", f.request_path()),
                Some(serde_json::to_value(&accept).unwrap()),
            )
            .await
            .0,
        );
        f.unchanged(&srv).await;
        let stop = en::revoked(&f.owner, &f.grant);
        let (status, body) = view_call(
            &srv,
            &view,
            &f.owner,
            Method::POST,
            &en::grants_path(f.id()),
            Some(
                serde_json::to_value(PublishOwnDevicesGrantRequest {
                    grant: stop.clone(),
                })
                .unwrap(),
            ),
        )
        .await;
        assert!(status.is_success());
        assert_eq!(
            serde_json::from_value::<SignedSharingOwnDevicesGrantState>(body).unwrap(),
            stop
        );
        let off = router_view(&srv, |c| {
            c.object_sharing_enabled = false;
            c.sharing_owner_online_enrollment_enabled = false;
            c.shared_groups_enabled = false;
            c.shared_secrets_enabled = false;
        })
        .await;
        assert_eq!(
            view_call(&srv, &off, &f.owner, Method::GET, &gpath, None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            view_call(
                &srv,
                &off,
                &f.owner,
                Method::POST,
                &en::grants_path(f.id()),
                Some(serde_json::to_value(PublishOwnDevicesGrantRequest { grant: stop }).unwrap())
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn signed_other_successors_preserve_counts_and_admission_budget_is_cumulative() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Automatic).await;
    let renewed = en::grant(
        &f.owner,
        &f.anchor,
        &f.old,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        3,
    );
    let omitted = en::grant(
        &f.owner,
        &f.anchor,
        &f.old,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        3,
    );
    en::publish_grant(&srv, &f.owner, &renewed).await;
    en::publish_grant(&srv, &f.owner, &omitted).await;
    let second_target = srv
        .new_device_session(&f.anchor, "second admitted target")
        .await;
    let old_pending = en::submission(&second_target, &f.anchor, &renewed, SharingRole::Reader);
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &second_target,
        &en::requests_path(f.id()),
        &old_pending,
    )
    .await;
    let mut accept = f.ready(&srv).await;
    accept.other_grant_successors = vec![en::successor(
        &f.owner,
        &renewed,
        &accept.rotation.access.manifest,
        0,
    )];
    en::resign_acceptance(&f.owner, &mut accept);
    for case in 0..3 {
        let mut bad = accept.clone();
        let other = &mut bad.other_grant_successors[0].grant;
        match case {
            0 => other.admitted_count = 1,
            1 => other.expires_at += 1,
            _ => other.previous_grant_state_hash = random::<32>().to_vec().into(),
        }
        bad.other_grant_successors[0] = en::sign_grant(&f.owner, other.clone());
        en::resign_acceptance(&f.owner, &mut bad);
        reject_post(
            &srv,
            &f.owner,
            &format!("{}/accept", f.request_path()),
            &bad,
        )
        .await;
        f.unchanged(&srv).await;
    }
    let result: OwnDeviceAcceptanceResult = en::post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &accept,
    )
    .await;
    assert_eq!(result.other_grant_successors, accept.other_grant_successors);
    let renewed_head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), renewed.grant.grant_id),
    )
    .await;
    assert_eq!(renewed_head.grant.admitted_count, 0);
    assert_eq!(renewed_head.grant.grant_revision, 2);
    assert_eq!(renewed_head.grant.access_epoch, 2);
    let omitted_head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), omitted.grant.grant_id),
    )
    .await;
    assert_eq!(omitted_head, omitted);
    let stale = en::submission(&second_target, &f.anchor, &omitted, SharingRole::Reader);
    reject_post(&srv, &second_target, &en::requests_path(f.id()), &stale).await;
    // An old pending signature cannot be retargeted to the renewed grant hash.
    let old_challenge = en::challenge(&f.owner, &old_pending, 1);
    reject_post(
        &srv,
        &f.owner,
        &format!(
            "{}/challenge",
            en::request_path(f.id(), old_pending.request.request.request_id)
        ),
        &PublishOwnDeviceChallengeRequest {
            challenge: old_challenge,
        },
    )
    .await;
    let fresh = en::submission(
        &second_target,
        &f.anchor,
        &result.consumed_grant_successor,
        SharingRole::Reader,
    );
    let _: OwnDeviceRequestState =
        en::post(&srv, &second_target, &en::requests_path(f.id()), &fresh).await;
    let (challenge, response) = en::respond(&srv, &f.owner, &second_target, &fresh).await;
    let exhaust = en::acceptance(
        &f.owner,
        &second_target,
        &result.state,
        &result.consumed_grant_successor,
        &fresh,
        &challenge,
        &response,
    );
    assert_eq!(
        exhaust.consumed_grant_successor.grant.status,
        EnrollmentGrantStatus::Revoked
    );
    let final_result: OwnDeviceAcceptanceResult = en::post(
        &srv,
        &f.owner,
        &format!(
            "{}/accept",
            en::request_path(f.id(), fresh.request.request.request_id)
        ),
        &exhaust,
    )
    .await;
    assert_eq!(
        final_result.consumed_grant_successor.grant.admitted_count,
        2
    );
    assert_eq!(
        final_result.consumed_grant_successor.grant.max_admissions,
        2
    );
    let third_target = srv.new_device_session(&f.anchor, "exhausted target").await;
    let denied = en::submission(
        &third_target,
        &f.anchor,
        &final_result.consumed_grant_successor,
        SharingRole::Reader,
    );
    reject_post(&srv, &third_target, &en::requests_path(f.id()), &denied).await;
    no_item_access(&srv, &third_target, f.id()).await;
}

#[tokio::test]
async fn grant_and_request_pages_are_bounded_ordered_and_anchor_scoped() {
    let srv = server!(enabled);
    let owner = srv.new_account().await;
    let anchor = srv.new_account().await;
    let other_anchor = srv.new_account().await;
    let old = create(
        &srv,
        &owner,
        &[
            (&anchor, SharingRole::Reader),
            (&other_anchor, SharingRole::Reader),
        ],
    )
    .await;
    let id = old.access.manifest.share_id;
    let mut grants = Vec::new();
    for a in [&anchor, &other_anchor, &anchor] {
        let g = en::grant(
            &owner,
            a,
            &old,
            SharingRole::Reader,
            EnrollmentMode::Manual,
            2,
        );
        en::publish_grant(&srv, &owner, &g).await;
        grants.push(g);
    }
    grants.sort_by_key(|g| g.grant.grant_id);
    let mut after = None;
    let mut found = Vec::new();
    for _ in 0..4 {
        let p = format!(
            "{}?limit=1{}",
            en::grants_path(id),
            after.map(|id| format!("&after={id}")).unwrap_or_default()
        );
        let page: OwnDevicesGrantPage = en::get(&srv, &owner, &p).await;
        validate_grant_page(&page, &en::scope(&old)).unwrap();
        assert!(page.items.len() <= 1);
        found.extend(page.items);
        if !page.has_more {
            break;
        }
        assert!(after.is_none_or(|id| page.next_after.unwrap() > id));
        after = page.next_after;
    }
    assert_eq!(found, grants);
    let page: OwnDevicesGrantPage = en::get(&srv, &anchor, &en::grants_path(id)).await;
    assert_eq!(
        page.items,
        grants
            .iter()
            .filter(|g| g.grant.anchor.device_id == anchor.device.id)
            .cloned()
            .collect::<Vec<_>>()
    );
    let hidden = grants
        .iter()
        .find(|g| g.grant.anchor.device_id == other_anchor.device.id)
        .unwrap();
    assert_eq!(
        srv.get(&en::grant_path(id, hidden.grant.grant_id), &anchor.access)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let grant = grants
        .iter()
        .find(|g| g.grant.anchor.device_id == anchor.device.id)
        .unwrap();
    let mut requests = Vec::new();
    for _ in 0..3 {
        let target = srv.new_device_session(&anchor, "paged target").await;
        let submission = en::submission(&target, &anchor, grant, SharingRole::Reader);
        let state: OwnDeviceRequestState =
            en::post(&srv, &target, &en::requests_path(id), &submission).await;
        requests.push(state);
    }
    requests.sort_by_key(|r| r.request.request.request_id);
    let mut after = None;
    let mut found = Vec::new();
    for _ in 0..4 {
        let p = format!(
            "{}?limit=1{}",
            en::requests_path(id),
            after.map(|id| format!("&after={id}")).unwrap_or_default()
        );
        let page: OwnDeviceRequestPage = en::get(&srv, &owner, &p).await;
        validate_request_page(&page, &en::scope(&old)).unwrap();
        assert!(page.items.len() <= 1);
        found.extend(page.items);
        if !page.has_more {
            break;
        }
        assert!(after.is_none_or(|id| page.next_after.unwrap() > id));
        after = page.next_after;
    }
    assert_eq!(found, requests);
    for p in [en::grants_path(id), en::requests_path(id)] {
        for suffix in [
            "?limit=0",
            "?limit=101",
            "?limit=1&limit=2",
            "?after=not-a-uuid",
        ] {
            assert_eq!(
                srv.get(&format!("{p}{suffix}"), &owner.access).await.0,
                StatusCode::BAD_REQUEST
            );
        }
    }
}

async fn hold_enrollment_item(
    srv: &TestServer,
    id: ShareId,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = srv.state.db.begin().await.unwrap();
    sqlx::query("SELECT id FROM shared_items WHERE id=$1 FOR UPDATE")
        .bind(Uuid::from(id))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}
async fn enrollment_waiters(srv: &TestServer, expected: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            // Each fixture uses its own database. Observe actual item-lock
            // contention without reading SQL parameters or signed documents.
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname=current_database() AND pid<>pg_backend_pid()
                   AND state='active' AND wait_event_type='Lock'
                   AND query LIKE '%FROM shared_items WHERE id=%'",
            )
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
            if waiting >= expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("enrollment operations did not reach the held item lock");
}
fn spawn_enrollment_post(
    srv: &TestServer,
    caller: &Session,
    p: &str,
    value: &impl Serialize,
) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let body = serde_json::to_vec(value).unwrap();
    let proof = srv.proof_for(&caller.access, "POST", p, &body).unwrap();
    let request = srv
        .http
        .post(srv.url(p))
        .bearer_auth(&caller.access)
        .header(cc_protocol::version::HEADER_DEVICE_PROOF, proof)
        .header("content-type", "application/json")
        .body(body);
    tokio::spawn(async move {
        let response = request.send().await.unwrap();
        let status = response.status();
        let body = response.json::<Value>().await.unwrap();
        (status, body)
    })
}
async fn completed_enrollment(
    task: tokio::task::JoinHandle<(StatusCode, Value)>,
) -> (StatusCode, Value) {
    tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .expect("enrollment did not finish after item lock release")
        .expect("enrollment HTTP task panicked")
}
async fn enrollment_counts(srv: &TestServer, f: &Fixture) -> (i64, i64, i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT
          (SELECT count(*) FROM shared_manifests WHERE share_id=$1),
          (SELECT count(*) FROM shared_revision_headers WHERE share_id=$1),
          (SELECT count(*) FROM shared_enrollment_grant_states WHERE share_id=$1 AND grant_id=$2),
          (SELECT count(*) FROM shared_item_devices WHERE share_id=$1 AND device_id=$3),
          (SELECT count(*) FROM audit_events WHERE target_id=$1 AND event_type='share_access_rotated'),
          (SELECT count(*) FROM audit_events WHERE target_id=$1 AND event_type='share_enrollment_accepted')",
    )
    .bind(Uuid::from(f.id()))
    .bind(f.grant.grant.grant_id)
    .bind(Uuid::from(f.target.device.id))
    .fetch_one(&srv.state.db)
    .await
    .unwrap()
}

#[tokio::test]
async fn acceptance_racing_terminal_grant_revoke_has_one_atomic_winner() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Automatic).await;
    let accept = f.ready(&srv).await;
    let stop = en::revoked(&f.owner, &f.grant);
    let held = hold_enrollment_item(&srv, f.id()).await;
    let accepting = spawn_enrollment_post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &accept,
    );
    let revoking = spawn_enrollment_post(
        &srv,
        &f.owner,
        &en::grants_path(f.id()),
        &PublishOwnDevicesGrantRequest {
            grant: stop.clone(),
        },
    );
    enrollment_waiters(&srv, 2).await;
    held.commit().await.unwrap();
    let accepted = completed_enrollment(accepting).await;
    let revoked = completed_enrollment(revoking).await;
    assert_ne!(
        accepted.0.is_success(),
        revoked.0.is_success(),
        "accept and grant CAS revoke cannot both commit"
    );
    let (item, expected_grant, counts, status, receipt) = if accepted.0.is_success() {
        assert_eq!(revoked.0, StatusCode::CONFLICT);
        let result: OwnDeviceAcceptanceResult = serde_json::from_value(accepted.1).unwrap();
        assert_eq!(result.acceptance, accept.acceptance);
        (
            result.state,
            result.consumed_grant_successor,
            (2, 2, 2, 1, 1, 1),
            OwnDeviceRequestStatus::Accepted,
            Some(result.acceptance),
        )
    } else {
        assert_eq!(accepted.0, StatusCode::CONFLICT);
        assert_eq!(
            serde_json::from_value::<SignedSharingOwnDevicesGrantState>(revoked.1).unwrap(),
            stop
        );
        (
            f.old.clone(),
            stop,
            (1, 1, 2, 0, 0, 0),
            OwnDeviceRequestStatus::Denied,
            None,
        )
    };
    let actual: SharedItemState = en::get(&srv, &f.owner, &path(f.id())).await;
    assert_eq!(actual, item);
    let grant: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), f.grant.grant.grant_id),
    )
    .await;
    assert_eq!(grant, expected_grant);
    let request: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
    assert_eq!(request.status, status);
    assert_eq!(request.acceptance, receipt);
    assert_eq!(enrollment_counts(&srv, &f).await, counts);
}

#[tokio::test]
async fn acceptance_racing_anchor_remove_or_downgrade_has_one_atomic_winner() {
    let srv = server!(enabled);
    for downgrade in [false, true] {
        let f = Fixture::new(&srv, SharingRole::Editor, EnrollmentMode::Manual).await;
        let accept = f.ready(&srv).await;
        let mut members = vec![member(&f.owner, SharingRole::Editor)];
        if downgrade {
            members.push(member(&f.anchor, SharingRole::Reader));
        }
        let rotate = rotation(&f.owner, &f.old, members);
        let held = hold_enrollment_item(&srv, f.id()).await;
        let accepting = spawn_enrollment_post(
            &srv,
            &f.owner,
            &format!("{}/accept", f.request_path()),
            &accept,
        );
        let rotating =
            spawn_enrollment_post(&srv, &f.owner, &format!("{}/access", path(f.id())), &rotate);
        enrollment_waiters(&srv, 2).await;
        held.commit().await.unwrap();
        let accepted = completed_enrollment(accepting).await;
        let rotated = completed_enrollment(rotating).await;
        assert_ne!(
            accepted.0.is_success(),
            rotated.0.is_success(),
            "accept and ordinary access CAS cannot both commit"
        );
        let (item, expected_grant, counts, status) = if accepted.0.is_success() {
            assert_eq!(rotated.0, StatusCode::CONFLICT);
            let result: OwnDeviceAcceptanceResult = serde_json::from_value(accepted.1).unwrap();
            (
                result.state,
                result.consumed_grant_successor,
                (2, 2, 2, 1, 1, 1),
                OwnDeviceRequestStatus::Accepted,
            )
        } else {
            assert_eq!(accepted.0, StatusCode::CONFLICT);
            let rotated: SharedItemState = serde_json::from_value(rotated.1).unwrap();
            assert_eq!(rotated.access, rotate.access);
            (
                rotated,
                f.grant.clone(),
                (2, 2, 1, 0, 1, 0),
                OwnDeviceRequestStatus::Denied,
            )
        };
        let actual: SharedItemState = en::get(&srv, &f.owner, &path(f.id())).await;
        assert_eq!(actual, item);
        let grant: SignedSharingOwnDevicesGrantState = en::get(
            &srv,
            &f.owner,
            &en::grant_path(f.id(), f.grant.grant.grant_id),
        )
        .await;
        assert_eq!(grant, expected_grant);
        let request: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
        assert_eq!(request.status, status);
        assert_eq!(
            request.acceptance.is_some(),
            status == OwnDeviceRequestStatus::Accepted
        );
        assert_eq!(enrollment_counts(&srv, &f).await, counts);
    }
}

#[tokio::test]
async fn challenge_expiry_during_acceptance_item_lock_wait_rolls_back_every_write() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    f.submit(&srv).await;
    let mut challenge = en::challenge(&f.owner, &f.submission, 1);
    challenge.challenge.expires_at = now_unix() + 4;
    challenge = en::sign_challenge(&f.owner, challenge.challenge);
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &f.owner,
        &format!("{}/challenge", f.request_path()),
        &PublishOwnDeviceChallengeRequest {
            challenge: challenge.clone(),
        },
    )
    .await;
    let response = en::response(&f.target, &challenge);
    let _: OwnDeviceRequestState = en::post(
        &srv,
        &f.target,
        &format!("{}/response", f.request_path()),
        &SubmitOwnDeviceChallengeResponseRequest {
            response: response.clone(),
        },
    )
    .await;
    let accept = en::acceptance(
        &f.owner,
        &f.target,
        &f.old,
        &f.grant,
        &f.submission,
        &challenge,
        &response,
    );
    let held = hold_enrollment_item(&srv, f.id()).await;
    let accepting = spawn_enrollment_post(
        &srv,
        &f.owner,
        &format!("{}/accept", f.request_path()),
        &accept,
    );
    enrollment_waiters(&srv, 1).await;
    assert!(
        now_unix() < challenge.challenge.expires_at,
        "test must observe waiting before challenge expiry"
    );
    let wait = (challenge.challenge.expires_at - now_unix()).max(0) as u64 + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    assert!(now_unix() < f.grant.grant.expires_at);
    assert!(now_unix() < f.submission.request.request.expires_at);
    held.commit().await.unwrap();
    assert_eq!(
        completed_enrollment(accepting).await.0,
        StatusCode::CONFLICT
    );
    f.unchanged(&srv).await;
    assert_eq!(enrollment_counts(&srv, &f).await, (1, 1, 1, 0, 0, 0));
    let stored: sqlx::types::Json<OwnDeviceRequestState> = sqlx::query_scalar(
        "SELECT document FROM shared_enrollment_requests WHERE share_id=$1 AND request_id=$2",
    )
    .bind(Uuid::from(f.id()))
    .bind(f.submission.request.request.request_id)
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(stored.status, OwnDeviceRequestStatus::Responded);
    assert_eq!(stored.challenge, Some(challenge));
    assert_eq!(stored.response, Some(response));
    assert!(stored.acceptance.is_none());
    no_item_access(&srv, &f.target, f.id()).await;
}

#[tokio::test]
async fn stale_grant_can_be_read_and_revoked_after_anchor_device_is_physically_missing() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Automatic).await;
    f.submit(&srv).await;
    // Use a valid v1 removal first, so no derived ACL FK or live permission
    // remains. This simulates later device-record purging, not a production API.
    let rotate = rotation(
        &f.owner,
        &f.old,
        vec![member(&f.owner, SharingRole::Editor)],
    );
    let _: SharedItemState =
        en::post(&srv, &f.owner, &format!("{}/access", path(f.id())), &rotate).await;
    assert_eq!(
        sqlx::query("DELETE FROM devices WHERE id=$1")
            .bind(Uuid::from(f.anchor.device.id))
            .execute(&srv.state.db)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    let view = router_view(&srv, |c| c.sharing_owner_online_enrollment_enabled = false).await;
    let p = en::grant_path(f.id(), f.grant.grant.grant_id);
    let (status, head) = view_call(&srv, &view, &f.owner, Method::GET, &p, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<SignedSharingOwnDevicesGrantState>(head).unwrap(),
        f.grant
    );
    assert_eq!(
        view_call(
            &srv,
            &view,
            &f.owner,
            Method::GET,
            &format!("{p}/history"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let stop = en::revoked(&f.owner, &f.grant);
    let (status, result) = view_call(
        &srv,
        &view,
        &f.owner,
        Method::POST,
        &en::grants_path(f.id()),
        Some(
            serde_json::to_value(PublishOwnDevicesGrantRequest {
                grant: stop.clone(),
            })
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<SignedSharingOwnDevicesGrantState>(result).unwrap(),
        stop
    );
    let history: OwnDevicesGrantHistoryPage =
        en::get(&srv, &f.owner, &format!("{p}/history")).await;
    assert_eq!(history.states, vec![f.grant.clone(), stop]);
    let request: OwnDeviceRequestState = en::get(&srv, &f.target, &f.request_path()).await;
    assert_eq!(request.status, OwnDeviceRequestStatus::Denied);
    no_item_access(&srv, &f.target, f.id()).await;
}

#[tokio::test]
async fn unrelated_callers_cannot_probe_revoked_participants_or_deleted_items() {
    let srv = server!(enabled);
    for scenario in 0..3 {
        let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
        let outsider = srv.new_account().await;
        f.ready(&srv).await;
        let before: sqlx::types::Json<OwnDeviceRequestState> = sqlx::query_scalar(
            "SELECT document FROM shared_enrollment_requests WHERE share_id=$1 AND request_id=$2",
        )
        .bind(Uuid::from(f.id()))
        .bind(f.submission.request.request.request_id)
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
        match scenario {
            0 | 1 => {
                let revoked = if scenario == 0 { &f.anchor } else { &f.target };
                assert_eq!(
                    srv.post(
                        &format!("/v1/devices/{}/revoke", revoked.device.id),
                        Some(&revoked.access),
                        &json!({})
                    )
                    .await
                    .0,
                    StatusCode::NO_CONTENT
                );
            }
            _ => {
                let mut deleted = revision(&f.owner, &f.old.access.manifest, Some(&f.old.revision));
                deleted.signed.mutation.operation = SharingOperation::Delete;
                deleted.body = None;
                sign_revision(&f.owner, &mut deleted);
                let _: SharedItemState = en::post(
                    &srv,
                    &f.owner,
                    &format!("{}/revisions", path(f.id())),
                    &PutSharedRevisionRequest { revision: deleted },
                )
                .await;
            }
        }
        let challenge = en::challenge(&f.owner, &f.submission, 2);
        let response = en::response(&f.target, &challenge);
        // Payloads have legitimate participant signatures; only the caller is
        // unrelated. Known and unknown request IDs must be indistinguishable.
        for request in [f.submission.request.request.request_id, Uuid::new_v4()] {
            let p = en::request_path(f.id(), request);
            assert_eq!(
                srv.post(
                    &format!("{p}/challenge"),
                    Some(&outsider.access),
                    &PublishOwnDeviceChallengeRequest {
                        challenge: challenge.clone()
                    }
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                srv.post(
                    &format!("{p}/response"),
                    Some(&outsider.access),
                    &SubmitOwnDeviceChallengeResponseRequest {
                        response: response.clone()
                    }
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
        }
        let after: sqlx::types::Json<OwnDeviceRequestState> = sqlx::query_scalar(
            "SELECT document FROM shared_enrollment_requests WHERE share_id=$1 AND request_id=$2",
        )
        .bind(Uuid::from(f.id()))
        .bind(f.submission.request.request.request_id)
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
        assert_eq!(after.0, before.0);
    }
}

#[tokio::test]
async fn grant_expiry_during_audit_insert_wait_rolls_back_head_history_and_audit() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv, SharingRole::Reader, EnrollmentMode::Manual).await;
    let mut grant = en::grant(
        &f.owner,
        &f.anchor,
        &f.old,
        SharingRole::Reader,
        EnrollmentMode::Automatic,
        1,
    );
    grant.grant.expires_at = now_unix() + 4;
    grant = en::sign_grant(&f.owner, grant.grant);
    let mut held = srv.state.db.begin().await.unwrap();
    // SHARE allows reads but conflicts with the ROW EXCLUSIVE lock needed by
    // audit INSERT. All earlier grant checks and provisional writes finish.
    sqlx::query("LOCK TABLE audit_events IN SHARE MODE")
        .execute(&mut *held)
        .await
        .unwrap();
    let publishing = spawn_enrollment_post(
        &srv,
        &f.owner,
        &en::grants_path(f.id()),
        &PublishOwnDevicesGrantRequest {
            grant: grant.clone(),
        },
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname=current_database() AND pid<>pg_backend_pid()
                   AND state='active' AND wait_event_type='Lock'
                   AND query LIKE '%INSERT INTO audit_events%'",
            )
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("grant publisher did not reach the held audit insert");
    assert!(
        now_unix() < grant.grant.expires_at,
        "publisher must reach audit before expiry"
    );
    let wait = (grant.grant.expires_at - now_unix()).max(0) as u64 + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    held.commit().await.unwrap();
    assert_eq!(
        completed_enrollment(publishing).await.0,
        StatusCode::CONFLICT
    );
    let grants: OwnDevicesGrantPage = en::get(&srv, &f.owner, &en::grants_path(f.id())).await;
    assert_eq!(grants.items, vec![f.grant.clone()]);
    assert_eq!(
        srv.get(
            &en::grant_path(f.id(), grant.grant.grant_id),
            &f.owner.access
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (heads, history, audit): (i64,i64,i64) = sqlx::query_as(
        "SELECT
         (SELECT count(*) FROM shared_enrollment_grants WHERE share_id=$1),
         (SELECT count(*) FROM shared_enrollment_grant_states WHERE share_id=$1),
         (SELECT count(*) FROM audit_events WHERE target_id=$1 AND event_type='share_enrollment_grant')",
    ).bind(Uuid::from(f.id())).fetch_one(&srv.state.db).await.unwrap();
    assert_eq!((heads, history, audit), (1, 1, 1));
    f.unchanged(&srv).await;
}
