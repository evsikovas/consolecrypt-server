// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Protocol 1.5: per-request device proofs (sender-constrained tokens).
//! A stolen access or refresh token is useless without the device key.

mod common;

use cc_protocol::auth::TokenPair;
use cc_protocol::version::HEADER_DEVICE_PROOF;
use cc_protocol::{paths, ObjectId};
use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};

/// Send `body` to `path` with `token` and an explicit proof header value.
async fn send(
    srv: &TestServer,
    method: reqwest::Method,
    path: &str,
    token: &str,
    body: Option<&Value>,
    proof: Option<String>,
) -> (StatusCode, Value) {
    let bytes = body
        .map(|b| serde_json::to_vec(b).unwrap())
        .unwrap_or_default();
    let mut req = srv.http.request(method, srv.url(path)).bearer_auth(token);
    if let Some(p) = proof {
        req = req.header(HEADER_DEVICE_PROOF, p);
    }
    if body.is_some() {
        req = req.header("content-type", "application/json").body(bytes);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn signed_clients_work_end_to_end_when_required() {
    let srv = server!(); // required by default
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    assert_eq!(
        srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)])
            .await
            .0,
        StatusCode::OK
    );
    let b = srv.new_device_session(&a, "B").await;
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    let (s, body) = srv.changes(&b, vault.id, 0).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let mut ws = ws_connect(&srv, &a.access).await.expect("signed upgrade");
    ws_event(&mut ws).await;

    // Signed refresh.
    let body = json!({ "refresh_token": a.refresh });
    let bytes = serde_json::to_vec(&body).unwrap();
    let proof = request_proof(
        a.device.id,
        &a.device.signing,
        "POST",
        paths::AUTH_REFRESH,
        &bytes,
        now_unix(),
    );
    let resp = srv
        .http
        .post(srv.url(paths::AUTH_REFRESH))
        .header(HEADER_DEVICE_PROOF, proof)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let pair: TokenPair = resp.json().await.unwrap();
    srv.register_signer(pair.access_token.expose_secret(), &a.device);
    assert_eq!(
        srv.get(paths::AUTH_ME, pair.access_token.expose_secret())
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn stolen_access_token_without_the_device_key_is_useless() {
    let srv = server!(); // required by default
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let stolen = a.access.clone();
    let thief = TestDevice::new("thief");
    let changes = format!("{}?vault_id={}&after=0", paths::SYNC_CHANGES, vault.id);

    // No proof.
    let (s, body) = send(&srv, reqwest::Method::GET, &changes, &stolen, None, None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "invalid_proof");
    assert_eq!(body["details"]["reason"], "missing");
    // Signed by the thief's key.
    let forged = request_proof(
        a.device.id,
        &thief.signing,
        "GET",
        &changes,
        b"",
        now_unix(),
    );
    let (s, body) = send(
        &srv,
        reqwest::Method::GET,
        &changes,
        &stolen,
        None,
        Some(forged),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "invalid_signature");
    // Malformed header.
    let (s, body) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &stolen,
        None,
        Some("garbage".into()),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "malformed");
    // The WebSocket upgrade needs a proof too.
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("{}{}", srv.ws_base, paths::EVENTS_WS),
    )
    .unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {stolen}").parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status().as_u16(), 422)
        }
        other => panic!(
            "upgrade without proof must fail, got {:?}",
            other.map(|_| ())
        ),
    }
    // A forged push changes nothing.
    let push = json!({"vault_id": vault.id, "device_id": a.device.id, "mutations": [delete(ObjectId::new(), 0)]});
    let bytes = serde_json::to_vec(&push).unwrap();
    let forged = request_proof(
        a.device.id,
        &thief.signing,
        "POST",
        paths::SYNC_PUSH,
        &bytes,
        now_unix(),
    );
    let (s, _) = send(
        &srv,
        reqwest::Method::POST,
        paths::SYNC_PUSH,
        &stolen,
        Some(&push),
        Some(forged),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        0
    );
}

#[tokio::test]
async fn proofs_bind_method_path_body_time_and_are_single_use() {
    let srv = server!(); // required by default
    let a = srv.new_account().await;
    let key = &a.device.signing;
    let id = a.device.id;

    // Replay of a valid proof.
    let proof = request_proof(id, key, "GET", paths::AUTH_ME, b"", now_unix());
    let (s, _) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &a.access,
        None,
        Some(proof.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &a.access,
        None,
        Some(proof),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "replayed");

    // Signed for another path.
    let proof = request_proof(id, key, "GET", paths::AUTH_ME, b"", now_unix());
    let (s, body) = send(
        &srv,
        reqwest::Method::GET,
        paths::DEVICES,
        &a.access,
        None,
        Some(proof),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "invalid_signature");

    // Signed for another query string.
    let v = cc_protocol::VaultId::new();
    let signed_path = format!("{}?vault_id={v}&after=5", paths::SYNC_CHANGES);
    let sent_path = format!("{}?vault_id={v}&after=0", paths::SYNC_CHANGES);
    let proof = request_proof(id, key, "GET", &signed_path, b"", now_unix());
    let (s, _) = send(
        &srv,
        reqwest::Method::GET,
        &sent_path,
        &a.access,
        None,
        Some(proof),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // Signed for another body.
    let rename = paths::fill(paths::DEVICE, &[("device_id", &id.to_string())]);
    let signed = serde_json::to_vec(&json!({"name": "innocent"})).unwrap();
    let proof = request_proof(id, key, "PATCH", &rename, &signed, now_unix());
    let (s, body) = send(
        &srv,
        reqwest::Method::PATCH,
        &rename,
        &a.access,
        Some(&json!({"name": "evil"})),
        Some(proof),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Signed for another method.
    let proof = request_proof(id, key, "POST", paths::AUTH_ME, b"", now_unix());
    let (s, _) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &a.access,
        None,
        Some(proof),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // Stale.
    let proof = request_proof(id, key, "GET", paths::AUTH_ME, b"", now_unix() - 600);
    let (s, body) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &a.access,
        None,
        Some(proof),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["details"]["reason"], "stale");
}

#[tokio::test]
async fn stolen_refresh_token_cannot_refresh_or_revoke_the_session() {
    let srv = server!(); // required by default
    let a = srv.new_account().await;
    let thief = TestDevice::new("thief");
    let body = json!({ "refresh_token": a.refresh });
    let bytes = serde_json::to_vec(&body).unwrap();

    for proof in [
        None,
        Some(request_proof(
            a.device.id,
            &thief.signing,
            "POST",
            paths::AUTH_REFRESH,
            &bytes,
            now_unix(),
        )),
    ] {
        let mut req = srv
            .http
            .post(srv.url(paths::AUTH_REFRESH))
            .header("content-type", "application/json")
            .body(bytes.clone());
        if let Some(p) = proof {
            req = req.header(HEADER_DEVICE_PROOF, p);
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    // The victim's session is intact and the token was not consumed.
    assert_eq!(srv.get(paths::AUTH_ME, &a.access).await.0, StatusCode::OK);
    let proof = request_proof(
        a.device.id,
        &a.device.signing,
        "POST",
        paths::AUTH_REFRESH,
        &bytes,
        now_unix(),
    );
    let resp = srv
        .http
        .post(srv.url(paths::AUTH_REFRESH))
        .header(HEADER_DEVICE_PROOF, proof)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'device_proof_failed'"
        )
        .await
            >= 2
    );
}

#[tokio::test]
async fn accept_mode_meters_missing_but_rejects_invalid() {
    // Explicit opt-out (migration of clients that do not sign yet).
    let srv = server!(|c| c.require_request_proof = false);
    let a = srv.new_account().await;
    let thief = TestDevice::new("thief");
    let (s, _) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &a.access,
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "missing proof passes while not required");
    let forged = request_proof(
        a.device.id,
        &thief.signing,
        "GET",
        paths::AUTH_ME,
        b"",
        now_unix(),
    );
    let (s, _) = send(
        &srv,
        reqwest::Method::GET,
        paths::AUTH_ME,
        &a.access,
        None,
        Some(forged),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a present but invalid proof is always rejected"
    );
}
