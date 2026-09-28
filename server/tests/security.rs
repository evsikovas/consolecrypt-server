// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Security regressions: tenant isolation / IDOR (404, never 403), auth
//! bypass, protocol gate, security headers, error bodies without echoed
//! input, zero-knowledge storage.

mod common;

use cc_protocol::{paths, DeviceId, EnvelopeId, ObjectId, VaultId};
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::json;

#[tokio::test]
async fn other_accounts_cannot_see_or_touch_a_vault() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    let x = srv.new_account().await;
    let v = vault.id.to_string();

    let (_, body) = srv.get(paths::VAULTS, &x.access).await;
    assert_eq!(body["vaults"].as_array().unwrap().len(), 0);

    let not_found = |status: StatusCode, body: &serde_json::Value, what: &str| {
        assert_eq!(status, StatusCode::NOT_FOUND, "{what}: {body}");
        assert_eq!(body["code"], "not_found", "{what}");
    };
    let (s, b) = srv
        .get(&paths::fill(paths::VAULT, &[("vault_id", &v)]), &x.access)
        .await;
    not_found(s, &b, "get vault");
    let (s, b) = srv
        .get(
            &paths::fill(paths::VAULT_ENVELOPES, &[("vault_id", &v)]),
            &x.access,
        )
        .await;
    not_found(s, &b, "list envelopes");
    let (s, b) = srv.changes(&x, vault.id, 0).await;
    not_found(s, &b, "changes");
    let (s, b) = srv
        .get(&format!("{}?vault_id={v}", paths::SYNC_SNAPSHOT), &x.access)
        .await;
    not_found(s, &b, "snapshot");
    let (s, b) = srv.push(&x, vault.id, vec![put(ObjectId::new(), 0)]).await;
    not_found(s, &b, "push");
    let (s, b) = srv
        .get(
            &format!("{}?vault_id={v}", paths::RECOVERY_VAULT_ENVELOPE),
            &x.access,
        )
        .await;
    not_found(s, &b, "recovery material");
    // Even with the correct vault access key (e.g. leaked), a non-member gets 404.
    let (s, b) = srv.attest(&x, &vault).await;
    not_found(s, &b, "attest");
    let (s, b) = srv
        .post(
            paths::RECOVERY_VAULT_PASSWORD_REPLACE,
            Some(&x.access),
            &json!({"vault_id": vault.id, "vault_access_key": vault.vak_bytes(), "envelope": password_envelope()}),
        )
        .await;
    not_found(s, &b, "replace password envelope");
    let (s, b) = srv
        .delete(
            &paths::fill(paths::VAULT, &[("vault_id", &v)]),
            &x.access,
            Some(&json!({"vault_access_key": vault.vak_bytes()})),
        )
        .await;
    not_found(s, &b, "delete vault");
    // Creating a vault with a taken id reveals only "exists", never data.
    let (s, _) = srv
        .post(
            paths::VAULTS,
            Some(&x.access),
            &vault.create_request(x.device.id),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Nothing changed.
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        1
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_key_envelopes WHERE revoked_at IS NULL")
            .await,
        3
    );
}

#[tokio::test]
async fn other_accounts_cannot_touch_devices() {
    let srv = server!();
    let a = srv.new_account().await;
    srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let (_, req) = srv.post(paths::DEVICES, Some(&b.access), &json!({})).await;
    let x = srv.new_account().await;
    let xv = srv.create_vault(&x).await;

    let (s, _) = srv
        .request::<()>(
            Method::POST,
            &device_path(paths::DEVICE_REVOKE, b.device.id),
            Some(&x.access),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = srv
        .request(
            Method::PATCH,
            &device_path(paths::DEVICE, a.device.id),
            Some(&x.access),
            Some(&json!({"name": "pwned"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let request_id: cc_protocol::DeviceRequestId =
        serde_json::from_value(req["request_id"].clone()).unwrap();
    let (s, _) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&x.access),
            &approve_body(&x.device, request_id, &b.device, &[xv.id], now_unix()),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = srv
        .post(
            &device_path(paths::DEVICE_REJECT, b.device.id),
            Some(&x.access),
            &json!({"request_id": request_id}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // X's device list never contains A's devices.
    let (_, list) = srv.get(paths::DEVICES, &x.access).await;
    assert_eq!(list["devices"].as_array().unwrap().len(), 1);
    assert!(list["pending_requests"].as_array().unwrap().is_empty());
    // A device cannot attest another device.
    let (s, _) = srv
        .post(
            &device_path(paths::DEVICE_ATTEST, b.device.id),
            Some(&a.access),
            &json!({"vault_id": xv.id, "vault_access_key": xv.vak_bytes(), "envelope": device_envelope(b.device.id)}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn random_ids_are_404() {
    let srv = server!();
    let a = srv.new_account().await;
    let v = VaultId::new().to_string();
    for path in [
        paths::fill(paths::VAULT, &[("vault_id", &v)]),
        paths::fill(paths::VAULT_ENVELOPES, &[("vault_id", &v)]),
        format!("{}?vault_id={v}&after=0", paths::SYNC_CHANGES),
    ] {
        let (s, _) = srv.get(&path, &a.access).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    let (s, _) = srv
        .request::<()>(
            Method::POST,
            &device_path(paths::DEVICE_REVOKE, DeviceId::new()),
            Some(&a.access),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let own = srv.create_vault(&a).await;
    let (s, _) = srv
        .delete(
            &paths::fill(
                paths::VAULT_ENVELOPE,
                &[
                    ("vault_id", &own.id.to_string()),
                    ("envelope_id", &EnvelopeId::new().to_string()),
                ],
            ),
            &a.access,
            Some(&json!({"vault_access_key": own.vak_bytes()})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, body) = srv.get("/v1/does-not-exist", &a.access).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
    let (s, _) = srv.get("/v1/vaults/not-a-uuid", &a.access).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn every_protected_route_requires_auth() {
    let srv = server!();
    let v = VaultId::new().to_string();
    let d = DeviceId::new().to_string();
    let routes = [
        (Method::POST, paths::AUTH_LOGOUT.to_owned()),
        (Method::GET, paths::AUTH_ME.to_owned()),
        (Method::POST, paths::AUTH_PASSWORD_CHANGE.to_owned()),
        (Method::GET, paths::DEVICES.to_owned()),
        (Method::POST, paths::DEVICES.to_owned()),
        (
            Method::PATCH,
            paths::fill(paths::DEVICE, &[("device_id", &d)]),
        ),
        (
            Method::POST,
            paths::fill(paths::DEVICE_APPROVE, &[("device_id", &d)]),
        ),
        (
            Method::POST,
            paths::fill(paths::DEVICE_REJECT, &[("device_id", &d)]),
        ),
        (
            Method::POST,
            paths::fill(paths::DEVICE_ATTEST, &[("device_id", &d)]),
        ),
        (
            Method::POST,
            paths::fill(paths::DEVICE_REVOKE, &[("device_id", &d)]),
        ),
        (Method::GET, paths::VAULTS.to_owned()),
        (Method::POST, paths::VAULTS.to_owned()),
        (Method::GET, paths::fill(paths::VAULT, &[("vault_id", &v)])),
        (
            Method::DELETE,
            paths::fill(paths::VAULT, &[("vault_id", &v)]),
        ),
        (
            Method::GET,
            paths::fill(paths::VAULT_ENVELOPES, &[("vault_id", &v)]),
        ),
        (
            Method::POST,
            paths::fill(paths::VAULT_ENVELOPES, &[("vault_id", &v)]),
        ),
        (Method::POST, paths::SYNC_PUSH.to_owned()),
        (
            Method::GET,
            format!("{}?vault_id={v}&after=0", paths::SYNC_CHANGES),
        ),
        (
            Method::GET,
            format!("{}?vault_id={v}", paths::SYNC_SNAPSHOT),
        ),
        (
            Method::GET,
            format!("{}?vault_id={v}", paths::RECOVERY_VAULT_ENVELOPE),
        ),
        (
            Method::POST,
            paths::RECOVERY_VAULT_PASSWORD_REPLACE.to_owned(),
        ),
        (
            Method::POST,
            paths::RECOVERY_VAULT_RECOVERY_REPLACE.to_owned(),
        ),
    ];
    for (method, path) in routes {
        let resp = srv
            .http
            .request(method.clone(), srv.url(&path))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(resp.headers()["www-authenticate"], "Bearer");
    }
}

#[tokio::test]
async fn protocol_gate_and_meta() {
    let srv = server!();
    let a = srv.new_account().await;
    let resp = srv
        .http
        .get(srv.url(paths::VAULTS))
        .bearer_auth(&a.access)
        .header("x-cc-protocol-version", "2.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "upgrade_required");
    assert_eq!(body["details"]["upgrade_required"], true);
    assert_eq!(body["details"]["minimum_supported_protocol"], "1.0");

    let resp = srv
        .http
        .get(srv.url(paths::VAULTS))
        .bearer_auth(&a.access)
        .header("x-cc-protocol-version", "banana")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let ok = srv
        .signed(
            srv.http.get(srv.url(paths::VAULTS)),
            &a.access,
            "GET",
            paths::VAULTS,
            b"",
        )
        .bearer_auth(&a.access)
        .header("x-cc-protocol-version", "1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    // /v1/meta never answers 426 so old clients learn they must upgrade.
    let meta: serde_json::Value = srv
        .http
        .get(srv.url(paths::META))
        .header("x-cc-protocol-version", "0.9")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["upgrade_required"], true);
    assert_eq!(
        meta["protocol_version"],
        cc_protocol::PROTOCOL_VERSION.to_string()
    );
    assert!(meta["source_code_url"]
        .as_str()
        .unwrap()
        .starts_with("https://"));
}

#[tokio::test]
async fn security_headers_and_request_ids() {
    let srv = server!();
    let rid = uuid::Uuid::now_v7().to_string();
    let resp = srv
        .http
        .get(srv.url(paths::AUTH_ME))
        .header("x-request-id", &rid)
        .send()
        .await
        .unwrap();
    let h = resp.headers().clone();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(h["strict-transport-security"]
        .to_str()
        .unwrap()
        .contains("max-age="));
    assert_eq!(h["x-request-id"], rid.as_str());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["request_id"], rid);

    // A non-UUID request id is replaced (no log injection).
    let resp = srv
        .http
        .get(srv.url(paths::META))
        .header("x-request-id", "evil\" injected=1")
        .send()
        .await
        .unwrap();
    let got = resp.headers()["x-request-id"].to_str().unwrap().to_owned();
    assert!(uuid::Uuid::parse_str(&got).is_ok());
}

#[tokio::test]
async fn error_bodies_never_echo_input() {
    let srv = server!();
    let marker = "ECHO-MARKER-9f3b2c";
    // Wrong type for password: serde would normally quote the value.
    let (s, body) = srv
        .post(
            paths::AUTH_REGISTER,
            None,
            &json!({"email": marker, "password": 424242424242u64, "device": marker}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let text = body.to_string();
    assert!(
        !text.contains(marker) && !text.contains("424242424242"),
        "{text}"
    );

    let resp = srv
        .http
        .post(srv.url(paths::AUTH_LOGIN))
        .header("content-type", "application/json")
        .body(format!("{{\"email\": \"{marker}\", "))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!resp.text().await.unwrap().contains(marker));

    let (s, body) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({"refresh_token": format!("ccr_{marker}")}),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(!body.to_string().contains(marker));
}

#[tokio::test]
async fn server_stores_only_opaque_material() {
    // The DB holds hashes of tokens and the VAK, never the values themselves.
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let hashes: Vec<Vec<u8>> = sqlx::query_scalar("SELECT access_token_hash FROM sessions")
        .fetch_all(&srv.state.db)
        .await
        .unwrap();
    assert!(hashes.iter().all(|h| h.len() == 32
        && !h
            .windows(8)
            .any(|w| a.access.as_bytes().windows(8).any(|x| x == w))));
    let verifier: Vec<u8> = sqlx::query_scalar("SELECT access_key_verifier FROM vaults")
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert_ne!(verifier, vault.vak.to_vec());
    assert_eq!(
        verifier,
        consolecrypt_server::crypto::sha256(&vault.vak).to_vec()
    );
    let phc: String = sqlx::query_scalar("SELECT password_hash FROM users")
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert!(phc.starts_with("$argon2id$"));
    assert!(!phc.contains(&a.password));
}

#[tokio::test]
async fn nul_and_control_characters_never_reach_the_database() {
    // Regression (found by tests/fuzz.rs): PostgreSQL rejects NUL in text, so
    // such input must be refused before any query, never answered with 500.
    let srv = server!();
    let d = TestDevice::new("d");
    let (s, _) = srv
        .login("a\u{0}@example.test", "whatever-password", &d)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = srv
        .register("a\u{0}@example.test", &random_password(), &d)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = srv
        .post(
            paths::AUTH_PASSWORD_FORGOT,
            None,
            &json!({"email": "a\u{0}@example.test"}),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let mut bad = TestDevice::new("x\u{0}y");
    bad.name = "x\u{0}y".into();
    let (s, _) = srv
        .register(&random_email(), &random_password(), &bad)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn password_alone_cannot_log_in_as_an_existing_trusted_device() {
    // Security review CRITICAL-1 / ADR-0006: device ids and public keys are
    // visible to every session of the account, so re-login as an existing
    // device must prove possession of its Ed25519 key.
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;

    // The attacker knows the password, logs in as a new device and reads D.
    let x = srv.new_device_session(&a, "attacker").await;
    let (_, list) = srv.get(paths::DEVICES, &x.access).await;
    let victim = list["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["device_id"] == a.device.id.to_string())
        .unwrap()
        .clone();
    let impersonation = json!({
        "device_id": victim["device_id"],
        "name": "Device A",
        "platform": "cli",
        "encryption_public_key": victim["encryption_public_key"],
        "signing_public_key": victim["signing_public_key"],
    });
    let attempt = |proof: Option<serde_json::Value>| {
        let mut body =
            json!({"email": a.email, "password": a.password, "device": impersonation.clone()});
        if let Some(p) = proof {
            body["device_proof"] = p;
        }
        let srv = &srv;
        async move { srv.post(paths::AUTH_LOGIN, None, &body).await }
    };

    // 1. No proof.
    let (s, body) = attempt(None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["details"]["reason"], "device_proof_required");
    // 2. A proof signed with the attacker's own key.
    let mut forger = TestDevice::new("forger");
    forger.id = a.device.id;
    let (s, body) = attempt(Some(forger.proof())).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "invalid_signature");
    assert!(body.get("tokens").is_none());

    // The real device logs in; its proof cannot be replayed.
    let nonce = random::<32>();
    let proof = a.device.proof_at(now_unix(), nonce);
    let (s, _) = srv
        .login_with_proof(&a.email, &a.password, &a.device, Some(proof.clone()))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = attempt(Some(proof)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "replayed");
    // Stale proofs are refused even with the right key.
    let (s, body) = srv
        .login_with_proof(
            &a.email,
            &a.password,
            &a.device,
            Some(a.device.proof_at(now_unix() - 3600, random::<32>())),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "stale");

    // Failures are audited; nothing was pulled by the attacker.
    assert!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'device_proof_failed'"
        )
        .await
            >= 3
    );
    assert_eq!(srv.changes(&x, vault.id, 0).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn new_device_proof_is_optional_but_verified_when_present() {
    let srv = server!();
    let a = srv.new_account().await;
    let fresh = TestDevice::new("fresh");
    let (s, _) = srv
        .login_with_proof(&a.email, &a.password, &fresh, None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let other = TestDevice::new("other");
    let mut wrong = TestDevice::new("wrong");
    wrong.id = other.id;
    let (s, _) = srv
        .login_with_proof(&a.email, &a.password, &other, Some(wrong.proof()))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn public_auth_endpoints_have_a_small_body_limit() {
    let srv = server!();
    let big = json!({"email": "x".repeat(100 * 1024), "password": "p", "device": {}});
    for path in [
        paths::AUTH_LOGIN,
        paths::AUTH_REGISTER,
        paths::AUTH_PASSWORD_FORGOT,
    ] {
        let (s, body) = srv.post(path, None, &big).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{path}: {body}");
    }
}

#[tokio::test]
async fn forwarded_for_uses_only_the_proxy_appended_entry() {
    let srv = server!(|c| c.trust_proxy_headers = true);
    let a = srv.new_account().await;
    let fail_login = |xff: &'static str| {
        let srv = &srv;
        let email = a.email.clone();
        let reg = a.device.registration();
        async move {
            srv.http
                .post(srv.url(paths::AUTH_LOGIN))
                .header("x-forwarded-for", xff)
                .json(&json!({"email": email, "password": "wrong-password-123", "device": reg}))
                .send()
                .await
                .unwrap()
        }
    };
    fail_login("198.51.100.66, 203.0.113.9").await;
    fail_login("203.0.113.10, unknown").await;
    let ips: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT ip_address FROM audit_events WHERE event_type = 'login_failed' ORDER BY occurred_at",
    )
    .fetch_all(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(ips[0].as_deref(), Some("203.0.113.9"));
    // Unparseable right-most entry → the TCP peer, never the client-supplied one.
    assert_eq!(ips[1].as_deref(), Some("127.0.0.1"));
}
