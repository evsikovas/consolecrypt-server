// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Vault key trust (protocol 1.11, audit H2): approval intent, approval v2
//! (signature over the approver keys, key commitments and envelope hashes,
//! handed to the approved device) and signed key-commitment records.

mod common;

use cc_protocol::canonical::{
    device_approval_message, device_approval_message_v2, device_envelope_hash_input,
    vault_key_commitment_message, ApprovedVaultKey,
};
use cc_protocol::devices::{DeviceTrustRequest, ListDevicesResponse};
use cc_protocol::meta::ServerInfo;
use cc_protocol::recovery::VaultRecoveryMaterial;
use cc_protocol::vaults::VaultKeyCommitmentsResponse;
use cc_protocol::{paths, Bytes, DeviceRequestId, VaultId};
use common::*;
use consolecrypt_server::config::{Config, Limit, LimitSpec, RateLimitMode};
use ed25519_dalek::Signer as _;
use reqwest::StatusCode;
use serde_json::{json, Value};

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

async fn own_request(srv: &TestServer, s: &Session) -> DeviceTrustRequest {
    let (status, body) = srv.get(paths::DEVICES, &s.access).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list: ListDevicesResponse = serde_json::from_value(body).unwrap();
    list.pending_requests
        .into_iter()
        .find(|r| r.device.device_id == s.device.id)
        .expect("own pending request")
}

async fn intent(
    srv: &TestServer,
    approver: &Session,
    new: &Session,
    request_id: DeviceRequestId,
) -> (StatusCode, Value) {
    srv.post(
        &device_path(paths::DEVICE_APPROVAL_INTENT, new.device.id),
        Some(&approver.access),
        &json!({ "request_id": request_id }),
    )
    .await
}

fn envelope_hash(env: &Value) -> [u8; 32] {
    let env: cc_protocol::envelopes::NewEnvelope = serde_json::from_value(env.clone()).unwrap();
    consolecrypt_server::crypto::sha256(&device_envelope_hash_input(
        env.metadata
            .ephemeral_public_key
            .as_ref()
            .unwrap()
            .as_slice(),
        env.nonce.as_slice(),
        env.ciphertext.as_slice(),
    ))
}

/// A v1 approval body plus a v2 block for `commitments` (one per vault).
fn approve_v2_body(
    approver: &TestDevice,
    request_id: DeviceRequestId,
    new_device: &TestDevice,
    vaults: &[(VaultId, [u8; 32])],
    issued_at: i64,
) -> Value {
    let ids: Vec<VaultId> = vaults.iter().map(|(v, _)| *v).collect();
    let mut body = approve_body(approver, request_id, new_device, &ids, issued_at);
    let mut keys = Vec::new();
    for (i, (vault_id, commitment)) in vaults.iter().enumerate() {
        keys.push(ApprovedVaultKey {
            vault_id: *vault_id,
            commitment: *commitment,
            envelope_sha256: envelope_hash(&body["envelopes"][i]["envelope"]),
        });
    }
    let msg = device_approval_message_v2(
        request_id,
        approver.id,
        &approver.encryption_public_key,
        &approver.signing_public_key(),
        new_device.id,
        &new_device.encryption_public_key,
        &new_device.signing_public_key(),
        issued_at,
        &keys,
    );
    let sig = approver.signing.sign(&msg).to_bytes();
    body["v2"] = json!({
        "vault_commitments": keys.iter().map(|k| json!({
            "vault_id": k.vault_id,
            "commitment": Bytes::new(k.commitment.to_vec()),
            "envelope_sha256": Bytes::new(k.envelope_sha256.to_vec()),
        })).collect::<Vec<_>>(),
        "signature_v2": Bytes::new(sig.to_vec()),
    });
    body
}

async fn material(srv: &TestServer, s: &Session, vault: VaultId) -> VaultRecoveryMaterial {
    let (status, body) = srv
        .get(
            &format!("{}?vault_id={vault}", paths::RECOVERY_VAULT_ENVELOPE),
            &s.access,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

#[tokio::test]
async fn meta_advertises_vrk_commitment() {
    let srv = server!();
    let (status, body) = srv.get(paths::META, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let info: ServerInfo = serde_json::from_value(body).unwrap();
    assert!(info.capabilities.vrk_commitment);
    assert_eq!(info.protocol_version, cc_protocol::PROTOCOL_VERSION);
}

#[tokio::test]
async fn approval_intent_announces_the_approver_to_the_new_device() {
    let srv = server!();
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let c = srv.new_device_session(&a, "C (untrusted)").await;
    let req = request_trust(&srv, &b, &[v1.id]).await;
    assert!(req.approver.is_none());

    // Self-intent, untrusted devices and unknown requests are refused.
    assert_eq!(
        intent(&srv, &b, &b, req.request_id).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, body) = intent(&srv, &c, &b, req.request_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "device_not_trusted");
    assert_eq!(
        intent(&srv, &a, &b, DeviceRequestId::new()).await.0,
        StatusCode::NOT_FOUND
    );

    let (status, body) = intent(&srv, &a, &b, req.request_id).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let seen = own_request(&srv, &b).await;
    let approver = seen.approver.expect("approver announced");
    assert_eq!(approver.device_id, a.device.id);
    assert_eq!(
        approver.signing_public_key.as_slice(),
        a.device.signing_public_key()
    );
    assert_eq!(
        approver.encryption_public_key.as_slice(),
        a.device.encryption_public_key
    );
}

#[tokio::test]
async fn approval_v2_is_verified_and_handed_to_the_new_device() {
    let srv = server!();
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let v2 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let req = request_trust(&srv, &b, &[]).await;
    assert_eq!(
        intent(&srv, &a, &b, req.request_id).await.0,
        StatusCode::NO_CONTENT
    );
    let path = device_path(paths::DEVICE_APPROVE, b.device.id);
    let now = now_unix();

    // Envelope hash that does not match the envelope → 400.
    let mut bad = approve_v2_body(
        &a.device,
        req.request_id,
        &b.device,
        &[(v1.id, [7; 32])],
        now,
    );
    bad["v2"]["vault_commitments"][0]["envelope_sha256"] = json!(Bytes::new(vec![0; 32]));
    assert_eq!(
        srv.post(&path, Some(&a.access), &bad).await.0,
        StatusCode::BAD_REQUEST
    );

    // Commitments must cover exactly the envelopes → 400.
    let mut partial = approve_v2_body(
        &a.device,
        req.request_id,
        &b.device,
        &[(v1.id, [7; 32]), (v2.id, [8; 32])],
        now,
    );
    partial["v2"]["vault_commitments"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert_eq!(
        srv.post(&path, Some(&a.access), &partial).await.0,
        StatusCode::BAD_REQUEST
    );

    // A v2 signature over a different commitment → 422, nothing stored.
    let mut forged = approve_v2_body(
        &a.device,
        req.request_id,
        &b.device,
        &[(v1.id, [7; 32])],
        now,
    );
    forged["v2"]["vault_commitments"][0]["commitment"] = json!(Bytes::new(vec![9; 32]));
    let (status, body) = srv.post(&path, Some(&a.access), &forged).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "invalid_proof");
    assert!(material(&srv, &b, v1.id).await.device_envelope.is_none());

    // Valid v1 + v2.
    let good = approve_v2_body(
        &a.device,
        req.request_id,
        &b.device,
        &[(v1.id, [7; 32]), (v2.id, [8; 32])],
        now,
    );
    let (status, body) = srv.post(&path, Some(&a.access), &good).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let m = material(&srv, &b, v1.id).await;
    let env = m.device_envelope.expect("device envelope");
    let approval = m.device_approval.expect("v2 approval handed to B");
    assert_eq!(approval.request_id, req.request_id);
    assert_eq!(approval.approver_device_id, a.device.id);
    assert_eq!(approval.issued_at, now);
    assert_eq!(approval.vault_commitments.len(), 2);
    let entry = approval
        .vault_commitments
        .iter()
        .find(|c| c.vault_id == v1.id)
        .unwrap();
    assert_eq!(entry.commitment.as_slice(), &[7; 32]);
    let hash = consolecrypt_server::crypto::sha256(&device_envelope_hash_input(
        env.metadata
            .ephemeral_public_key
            .as_ref()
            .unwrap()
            .as_slice(),
        env.nonce.as_slice(),
        env.ciphertext.as_slice(),
    ));
    assert_eq!(entry.envelope_sha256.as_slice(), &hash);
    // The stored signature verifies as the new device would check it.
    let keys: Vec<ApprovedVaultKey> = approval
        .vault_commitments
        .iter()
        .map(|c| ApprovedVaultKey {
            vault_id: c.vault_id,
            commitment: c.commitment.to_array().unwrap(),
            envelope_sha256: c.envelope_sha256.to_array().unwrap(),
        })
        .collect();
    let msg = device_approval_message_v2(
        req.request_id,
        a.device.id,
        &a.device.encryption_public_key,
        &a.device.signing_public_key(),
        b.device.id,
        &b.device.encryption_public_key,
        &b.device.signing_public_key(),
        now,
        &keys,
    );
    assert!(consolecrypt_server::crypto::verify_ed25519(
        &a.device.signing_public_key(),
        &msg,
        approval.signature_v2.as_slice()
    ));
    // Other devices never receive B's approval.
    assert!(material(&srv, &a, v1.id).await.device_approval.is_none());
}

#[tokio::test]
async fn v1_approval_still_works_without_v2() {
    let srv = server!();
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let req = request_trust(&srv, &b, &[v1.id]).await;
    let (status, body) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(&a.device, req.request_id, &b.device, &[v1.id], now_unix()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let m = material(&srv, &b, v1.id).await;
    assert!(m.device_envelope.is_some());
    assert!(m.device_approval.is_none());
    // Unused import guard: the v1 message helper is the same as before.
    let _ = device_approval_message;
}

fn commitment_body(device: &TestDevice, vault: VaultId, c: [u8; 32], issued_at: i64) -> Value {
    let msg = vault_key_commitment_message(vault, &c, device.id, issued_at);
    json!({
        "device_id": device.id,
        "commitment": Bytes::new(c.to_vec()),
        "issued_at": issued_at,
        "signature": Bytes::new(device.signing.sign(&msg).to_bytes().to_vec()),
    })
}

async fn put_commitment(srv: &TestServer, s: &Session, vault: VaultId, body: &Value) -> StatusCode {
    let path = paths::fill(
        paths::VAULT_KEY_COMMITMENTS,
        &[("vault_id", &vault.to_string())],
    );
    srv.request(reqwest::Method::PUT, &path, Some(&s.access), Some(body))
        .await
        .0
}

async fn list_commitments(srv: &TestServer, s: &Session, vault: VaultId) -> (StatusCode, Value) {
    let path = paths::fill(
        paths::VAULT_KEY_COMMITMENTS,
        &[("vault_id", &vault.to_string())],
    );
    srv.get(&path, &s.access).await
}

#[tokio::test]
async fn key_commitments_are_signed_per_device_and_listed() {
    let srv = server!();
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B (untrusted)").await;
    let now = now_unix();

    // Untrusted devices cannot publish; a foreign device id or a bad
    // signature is refused; stale issued_at too.
    assert_eq!(
        put_commitment(
            &srv,
            &b,
            v1.id,
            &commitment_body(&b.device, v1.id, [1; 32], now)
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        put_commitment(
            &srv,
            &a,
            v1.id,
            &commitment_body(&b.device, v1.id, [1; 32], now)
        )
        .await,
        StatusCode::FORBIDDEN
    );
    let mut bad = commitment_body(&a.device, v1.id, [1; 32], now);
    bad["commitment"] = json!(Bytes::new(vec![2; 32]));
    assert_eq!(
        put_commitment(&srv, &a, v1.id, &bad).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        put_commitment(
            &srv,
            &a,
            v1.id,
            &commitment_body(&a.device, v1.id, [1; 32], now - 3600)
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    assert_eq!(
        put_commitment(
            &srv,
            &a,
            v1.id,
            &commitment_body(&a.device, v1.id, [1; 32], now)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    // An older record never replaces a newer one.
    assert_eq!(
        put_commitment(
            &srv,
            &a,
            v1.id,
            &commitment_body(&a.device, v1.id, [3; 32], now - 10)
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // Any active device of the member may read (the untrusted one too).
    let (status, body) = list_commitments(&srv, &b, v1.id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list: VaultKeyCommitmentsResponse = serde_json::from_value(body).unwrap();
    assert_eq!(list.commitments.len(), 1);
    let rec = &list.commitments[0];
    assert_eq!(rec.device_id, a.device.id);
    assert_eq!(rec.commitment.as_slice(), &[1; 32]);
    assert!(consolecrypt_server::crypto::verify_ed25519(
        &a.device.signing_public_key(),
        &vault_key_commitment_message(v1.id, &[1; 32], a.device.id, rec.issued_at),
        rec.signature.as_slice()
    ));

    // Another account sees nothing (404, no IDOR).
    let other = srv.new_account().await;
    assert_eq!(
        list_commitments(&srv, &other, v1.id).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn approval_intents_and_commitments_share_the_verification_limit() {
    let srv = server!(|c: &mut Config| {
        c.rate_limits.enabled = true;
        c.rate_limits.mode = RateLimitMode::Enforce;
        c.rate_limits
            .limits
            .set(Limit::VerificationAccount, LimitSpec::per_minute(1));
    });
    let a = srv.new_account().await;
    let v1 = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let req = request_trust(&srv, &b, &[v1.id]).await;

    let (status, body) = intent(&srv, &a, &b, req.request_id).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let path = paths::fill(
        paths::VAULT_KEY_COMMITMENTS,
        &[("vault_id", &v1.id.to_string())],
    );
    let (status, body) = srv
        .request(
            reqwest::Method::PUT,
            &path,
            Some(&a.access),
            Some(&commitment_body(&a.device, v1.id, [1; 32], now_unix())),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["details"]["limit"], "verification_account");
    let (status, body) = intent(&srv, &a, &b, req.request_id).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["details"]["limit"], "verification_account");
}
