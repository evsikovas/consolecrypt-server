// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! No secrets in logs: run the security-sensitive flows with TRACE logging
//! captured and assert that no password, token, access key, envelope,
//! signature or ciphertext appears anywhere in the output.
//!
//! Own test binary so it can install a process-wide subscriber.

mod common;

use cc_protocol::sync::MutationOp;
use cc_protocol::{paths, ObjectId};
use common::*;
use consolecrypt_server::mail::MailKind;
use reqwest::StatusCode;
use serde_json::json;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture() -> &'static Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let cap = Capture::default();
        let writer = cap.clone();
        // Everything at TRACE except the in-process *test clients* (reqwest,
        // the tungstenite client handshake — which logs request headers
        // incl. Authorization at TRACE), which are not part of the server.
        let filter = tracing_subscriber::EnvFilter::new(
            "trace,reqwest=off,hyper_util::client=off,tungstenite::handshake::client=off",
        );
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_writer(move || writer.clone())
            .init();
        cap
    })
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secrets_never_reach_the_logs() {
    let cap = capture();
    let srv = server!();
    let mut secrets: Vec<(String, String)> = Vec::new();

    let a = srv.new_account().await;
    secrets.push(("password".into(), a.password.clone()));
    secrets.push(("access token".into(), a.access.clone()));
    secrets.push(("refresh token".into(), a.refresh.clone()));

    // Vault creation: VAK and envelopes.
    let vault = TestVault::new();
    let req = vault.create_request(a.device.id);
    for env in [
        &req.password_envelope,
        &req.recovery_envelope,
        &req.device_envelope,
    ] {
        secrets.push(("envelope ciphertext".into(), b64(env.ciphertext.as_slice())));
    }
    secrets.push(("vault access key".into(), b64(&vault.vak)));
    let (s, _) = srv.post(paths::VAULTS, Some(&a.access), &req).await;
    assert_eq!(s, StatusCode::CREATED);

    // Push + pull ciphertext.
    let m = put(ObjectId::new(), 0);
    if let MutationOp::Put { body } = &m.op {
        secrets.push((
            "object ciphertext".into(),
            b64(&body.ciphertext.as_slice()[..48]),
        ));
        secrets.push(("wrapped dek".into(), b64(body.wrapped_dek.as_slice())));
    }
    assert_eq!(srv.push(&a, vault.id, vec![m]).await.0, StatusCode::OK);
    assert_eq!(srv.changes(&a, vault.id, 0).await.0, StatusCode::OK);

    // Second device: trust request + signed approval.
    let b = srv.new_device_session(&a, "B").await;
    secrets.push(("access token B".into(), b.access.clone()));
    let (_, req) = srv.post(paths::DEVICES, Some(&b.access), &json!({})).await;
    let request_id = serde_json::from_value(req["request_id"].clone()).unwrap();
    let approval = approve_body(&a.device, request_id, &b.device, &[vault.id], now_unix());
    secrets.push((
        "signature".into(),
        approval["signature"].as_str().unwrap().to_owned(),
    ));
    let (s, _) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approval,
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // Wrong vault access key (failure paths log too).
    let (s, _) = srv
        .attest(
            &b,
            &TestVault {
                id: vault.id,
                vak: random::<32>(),
            },
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // Refresh (rotation) and reuse.
    let (_, pair) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({"refresh_token": a.refresh}),
        )
        .await;
    secrets.push((
        "rotated access".into(),
        pair["access_token"].as_str().unwrap().to_owned(),
    ));
    secrets.push((
        "rotated refresh".into(),
        pair["refresh_token"].as_str().unwrap().to_owned(),
    ));
    srv.post(
        paths::AUTH_REFRESH,
        None,
        &json!({"refresh_token": a.refresh}),
    )
    .await;

    // Failed login with a wrong password.
    let wrong = random_password();
    secrets.push(("wrong password".into(), wrong.clone()));
    srv.login(&a.email, &wrong, &a.device).await;

    // Password reset with a mailed token.
    srv.post(
        paths::AUTH_PASSWORD_FORGOT,
        None,
        &json!({"email": a.email}),
    )
    .await;
    let token = loop {
        if let Some(t) = srv.mailer.token_for(&a.email, MailKind::PasswordReset) {
            break t;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    let new_password = random_password();
    secrets.push(("reset token".into(), token.clone()));
    secrets.push(("new password".into(), new_password.clone()));
    let (s, _) = srv
        .post(
            paths::AUTH_PASSWORD_RESET,
            None,
            &json!({"token": token, "new_password": new_password}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // WebSocket with a bearer token.
    let c = srv
        .new_device_session(
            &Session {
                password: new_password.clone(),
                ..a
            },
            "C",
        )
        .await;
    secrets.push(("access token C".into(), c.access.clone()));
    let mut ws = ws_connect(&srv, &c.access).await.unwrap();
    ws_event(&mut ws).await;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("\"route\":\"/v1/sync/push\""),
        "the capture must actually contain server request logs"
    );
    for (what, value) in &secrets {
        assert!(!value.is_empty());
        if let Some(line) = logs.lines().find(|l| l.contains(value.as_str())) {
            let target = serde_json::from_str::<serde_json::Value>(line)
                .map(|v| v["target"].to_string())
                .unwrap_or_default();
            panic!("{what} leaked into logs (target {target})");
        }
    }
    // Header values never logged.
    assert!(!logs.to_lowercase().contains("bearer cca_"));
}
