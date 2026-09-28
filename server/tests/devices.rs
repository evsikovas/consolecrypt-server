// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Device trust (ADR-0004): trust requests, signed approval, reject,
//! attestation, revocation, rename.

mod common;

use cc_protocol::devices::{DeviceStatus, DeviceTrustRequest, ListDevicesResponse};
use cc_protocol::{paths, DeviceRequestId, ObjectId, VaultId};
use common::*;
use reqwest::StatusCode;
use serde_json::json;

async fn request_trust(srv: &TestServer, s: &Session, vaults: &[VaultId]) -> DeviceTrustRequest {
    let (status, body) = srv
        .post(
            paths::DEVICES,
            Some(&s.access),
            &json!({ "vault_ids": vaults }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    serde_json::from_value(body).unwrap()
}

async fn devices(srv: &TestServer, s: &Session) -> ListDevicesResponse {
    let (status, body) = srv.get(paths::DEVICES, &s.access).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

#[tokio::test]
async fn approve_subset_with_valid_signature() {
    let srv = server!();
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let v2 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;

    // Empty list expands to every accessible vault, explicitly.
    let req = request_trust(&srv, &b, &[]).await;
    let mut expected = vec![v1.id, v2.id];
    expected.sort();
    assert_eq!(req.vault_ids, expected);
    assert_eq!(req.device.device_id, b.device.id);
    assert_eq!(
        req.device.signing_public_key.as_slice(),
        b.device.signing_public_key()
    );

    // A sees the pending request with B's keys (for the verification code).
    let list = devices(&srv, &a).await;
    assert_eq!(list.pending_requests.len(), 1);
    assert_eq!(list.pending_requests[0].request_id, req.request_id);

    // Approve only v1.
    let (status, body) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(&a.device, req.request_id, &b.device, &[v1.id], now_unix()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let done: DeviceTrustRequest = serde_json::from_value(body).unwrap();
    assert_eq!(
        done.status,
        cc_protocol::devices::DeviceRequestStatus::Approved
    );
    assert_eq!(done.approved_by_device_id, Some(a.device.id));

    assert_eq!(srv.changes(&b, v1.id, 0).await.0, StatusCode::OK);
    assert_eq!(srv.changes(&b, v2.id, 0).await.0, StatusCode::FORBIDDEN);
    let list = devices(&srv, &b).await;
    let me = list.devices.iter().find(|d| d.is_current).unwrap();
    assert_eq!(me.trusted_vaults, vec![v1.id]);
    assert!(list.pending_requests.is_empty());

    // Replaying the same approval → 410 (request no longer pending).
    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(&a.device, req.request_id, &b.device, &[v1.id], now_unix()),
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn approval_signature_must_be_valid_and_fresh() {
    let srv = server!();
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let v2 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let req = request_trust(&srv, &b, &[]).await;
    let approve = |body: serde_json::Value| {
        let srv = &srv;
        let a = &a;
        let b = &b;
        async move {
            srv.post(
                &device_path(paths::DEVICE_APPROVE, b.device.id),
                Some(&a.access),
                &body,
            )
            .await
        }
    };

    // Signed by a different key claiming to be A's device.
    let mut forger = TestDevice::new("forger");
    forger.id = a.device.id;
    let (status, body) = approve(approve_body(
        &forger,
        req.request_id,
        &b.device,
        &[v1.id],
        now_unix(),
    ))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "invalid_proof");

    // Signature over v1 but envelopes for v1+v2 (vault list tampered).
    let mut body = approve_body(&a.device, req.request_id, &b.device, &[v1.id], now_unix());
    let extra = approve_body(&a.device, req.request_id, &b.device, &[v2.id], now_unix());
    body["envelopes"]
        .as_array_mut()
        .unwrap()
        .push(extra["envelopes"][0].clone());
    let (status, _) = approve(body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Stale issued_at.
    let (status, _) = approve(approve_body(
        &a.device,
        req.request_id,
        &b.device,
        &[v1.id],
        now_unix() - 3600,
    ))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Vault not in the request / unknown request.
    let v3 = srv.create_vault(&a).await;
    let (status, _) = approve(approve_body(
        &a.device,
        req.request_id,
        &b.device,
        &[v3.id],
        now_unix(),
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = approve(approve_body(
        &a.device,
        DeviceRequestId::new(),
        &b.device,
        &[v1.id],
        now_unix(),
    ))
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Still untrusted, request still pending; failures audited.
    assert_eq!(srv.changes(&b, v1.id, 0).await.0, StatusCode::FORBIDDEN);
    assert!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'device_approval_failed'"
        )
        .await
            >= 2
    );
    let (status, _) = approve(approve_body(
        &a.device,
        req.request_id,
        &b.device,
        &[v1.id, v2.id],
        now_unix(),
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn only_trusted_devices_approve_or_reject() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let c = srv.new_device_session(&a, "C").await;
    let req = request_trust(&srv, &b, &[]).await;

    // C is untrusted: cannot approve or reject.
    let (status, body) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&c.access),
            &approve_body(
                &c.device,
                req.request_id,
                &b.device,
                &[vault.id],
                now_unix(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "device_not_trusted");
    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_REJECT, b.device.id),
            Some(&c.access),
            &json!({ "request_id": req.request_id }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // B cannot approve itself.
    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&b.access),
            &approve_body(
                &b.device,
                req.request_id,
                &b.device,
                &[vault.id],
                now_unix(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A rejects.
    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_REJECT, b.device.id),
            Some(&a.access),
            &json!({ "request_id": req.request_id }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(
                &a.device,
                req.request_id,
                &b.device,
                &[vault.id],
                now_unix(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
    assert!(devices(&srv, &a).await.pending_requests.is_empty());
}

#[tokio::test]
async fn expired_requests_cannot_be_approved() {
    let srv = server!(|c| c.device_request_ttl = std::time::Duration::from_secs(0));
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let req = request_trust(&srv, &b, &[]).await;
    assert_eq!(
        req.status,
        cc_protocol::devices::DeviceRequestStatus::Expired
    );
    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(
                &a.device,
                req.request_id,
                &b.device,
                &[vault.id],
                now_unix(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn trust_request_validation() {
    let srv = server!();
    let a = srv.new_account().await;
    // No vaults yet.
    let (status, _) = srv.post(paths::DEVICES, Some(&a.access), &json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A vault of another account is invisible.
    let other = srv.new_account().await;
    let foreign = srv.create_vault(&other).await;
    srv.create_vault(&a).await;
    let (status, _) = srv
        .post(
            paths::DEVICES,
            Some(&a.access),
            &json!({ "vault_ids": [foreign.id] }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A new request supersedes the previous pending one.
    let b = srv.new_device_session(&a, "B").await;
    let first = request_trust(&srv, &b, &[]).await;
    let second = request_trust(&srv, &b, &[]).await;
    let pending = devices(&srv, &a).await.pending_requests;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request_id, second.request_id);
    assert_ne!(first.request_id, second.request_id);
}

#[tokio::test]
async fn revocation_kills_everything() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    assert_eq!(
        srv.push(&b, vault.id, vec![put(ObjectId::new(), 0)])
            .await
            .0,
        StatusCode::OK
    );

    // B (e.g. stolen) is revoked from A.
    let (status, _) = srv
        .request::<()>(
            reqwest::Method::POST,
            &device_path(paths::DEVICE_REVOKE, b.device.id),
            Some(&a.access),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // B's token is dead with a distinct code; B cannot sync or refresh.
    let (status, body) = srv.get(paths::AUTH_ME, &b.access).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "device_revoked");
    assert_eq!(
        srv.push(&b, vault.id, vec![put(ObjectId::new(), 0)])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(srv.changes(&b, vault.id, 0).await.0, StatusCode::FORBIDDEN);
    let (status, _) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({ "refresh_token": b.refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Logging in again with the revoked identity is refused.
    let (status, body) = srv.login(&a.email, &a.password, &b.device).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "device_revoked");

    // A sees B revoked with no trusted vaults; B's envelope is revoked.
    let list = devices(&srv, &a).await;
    let bi = list
        .devices
        .iter()
        .find(|d| d.device_id == b.device.id)
        .unwrap();
    assert_eq!(bi.status, DeviceStatus::Revoked);
    assert!(bi.trusted_vaults.is_empty());
    assert!(bi.revoked_at.is_some());
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM vault_key_envelopes
              WHERE recipient_type = 'device' AND revoked_at IS NULL"
        )
        .await,
        1
    );
    // Idempotent.
    let (status, _) = srv
        .request::<()>(
            reqwest::Method::POST,
            &device_path(paths::DEVICE_REVOKE, b.device.id),
            Some(&a.access),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn rename_device() {
    let srv = server!();
    let a = srv.new_account().await;
    let b = srv.new_device_session(&a, "B").await;
    let (status, body) = srv
        .request(
            reqwest::Method::PATCH,
            &device_path(paths::DEVICE, b.device.id),
            Some(&a.access),
            Some(&json!({ "name": "Office desktop" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Office desktop");
    assert_eq!(body["is_current"], false);
    let (status, _) = srv
        .request(
            reqwest::Method::PATCH,
            &device_path(paths::DEVICE, b.device.id),
            Some(&a.access),
            Some(&json!({ "name": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
