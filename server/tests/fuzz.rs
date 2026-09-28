// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Structured fuzzing of the JSON API: valid request bodies are mutated at
//! random (fields dropped, types swapped, invalid base64, huge / negative
//! numbers, deep nesting, odd unicode) and random bytes are sent. The server
//! must never answer 5xx, and every error must be a well-formed `ApiError`.
//!
//! Deterministic (seeded xorshift) so failures reproduce; set
//! `CC_FUZZ_ITERATIONS` / `CC_FUZZ_SEED` to explore more.

mod common;

use cc_protocol::{paths, ApiError, ObjectId};
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn weird_value(rng: &mut Rng) -> Value {
    match rng.below(14) {
        0 => Value::Null,
        1 => json!(true),
        2 => json!(-1),
        3 => json!(i64::MAX),
        4 => json!(u64::MAX),
        5 => json!(1.5e308),
        6 => json!(""),
        7 => json!("not base64 !!!"),
        8 => json!("\u{0000}\u{202e}\u{1F600}"),
        9 => json!("x".repeat(70_000)),
        10 => json!([]),
        11 => json!({}),
        12 => {
            let mut v = json!(1);
            for _ in 0..200 {
                v = json!([v]);
            }
            v
        }
        _ => json!("00000000-0000-0000-0000-000000000000"),
    }
}

/// Apply one random mutation somewhere inside `v`.
fn mutate(v: &mut Value, rng: &mut Rng) {
    match v {
        Value::Object(map) if !map.is_empty() => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let key = keys[rng.below(keys.len())].clone();
            match rng.below(4) {
                0 => {
                    map.remove(&key);
                }
                1 => {
                    map.insert(key, weird_value(rng));
                }
                2 => {
                    map.insert(format!("extra_{}", rng.below(100)), weird_value(rng));
                }
                _ => mutate(map.get_mut(&key).unwrap(), rng),
            }
        }
        Value::Array(items) if !items.is_empty() => {
            let i = rng.below(items.len());
            if rng.below(3) == 0 {
                items.remove(i);
            } else {
                mutate(&mut items[i], rng);
            }
        }
        other => *other = weird_value(rng),
    }
}

async fn send(
    srv: &TestServer,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut req = srv.http.request(method.clone(), srv.url(path));
    if let Some(t) = token {
        // Sign the mutated bytes so the fuzzed body reaches the handlers.
        req = srv
            .signed(req, t, method.as_str(), path, &body)
            .bearer_auth(t);
    }
    let req = req.header("content-type", "application/json").body(body);
    let resp = req.send().await.unwrap();
    let status = resp.status();
    (status, resp.bytes().await.unwrap().to_vec())
}

fn check(status: StatusCode, body: &[u8], what: &str) {
    assert!(
        !status.is_server_error(),
        "{what} → {status}: {}",
        String::from_utf8_lossy(body)
    );
    if !status.is_success() && status != StatusCode::SWITCHING_PROTOCOLS {
        let api_error = serde_json::from_slice::<ApiError>(body).is_ok();
        // A push with conflicts answers 409 with a full PushResponse (ADR-0003).
        let push_conflict = status == StatusCode::CONFLICT
            && serde_json::from_slice::<cc_protocol::sync::PushResponse>(body).is_ok();
        assert!(
            api_error || push_conflict,
            "{what} → {status}: error body is not an ApiError"
        );
    }
}

#[tokio::test]
async fn mutated_requests_never_cause_server_errors() {
    let srv = server!();
    let iterations: usize = std::env::var("CC_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25);
    let seed: u64 = std::env::var("CC_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5eed_c0ffee);
    let mut rng = Rng(seed);

    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    let b = srv.new_device_session(&a, "B").await;
    let (_, req) = srv.post(paths::DEVICES, Some(&b.access), &json!({})).await;
    let request_id = serde_json::from_value(req["request_id"].clone()).unwrap();
    let v = vault.id.to_string();

    // (method, path, token, valid body)
    let samples: Vec<(Method, String, Option<String>, Value)> = vec![
        (
            Method::POST,
            paths::AUTH_REGISTER.into(),
            None,
            json!({"email": random_email(), "password": random_password(), "device": TestDevice::new("f").registration()}),
        ),
        (
            Method::POST,
            paths::AUTH_LOGIN.into(),
            None,
            json!({"email": a.email, "password": "wrong-password-xx", "device": a.device.registration(), "device_proof": a.device.proof()}),
        ),
        (
            Method::POST,
            paths::AUTH_REFRESH.into(),
            None,
            json!({"refresh_token": "ccr_x"}),
        ),
        (
            Method::POST,
            paths::AUTH_PASSWORD_RESET.into(),
            None,
            json!({"token": "cct_x", "new_password": random_password()}),
        ),
        (
            Method::POST,
            paths::AUTH_PASSWORD_CHANGE.into(),
            Some(a.access.clone()),
            json!({"current_password": "wrong-password-xx", "new_password": random_password()}),
        ),
        (
            Method::POST,
            paths::VAULTS.into(),
            Some(a.access.clone()),
            serde_json::to_value(TestVault::new().create_request(a.device.id)).unwrap(),
        ),
        (
            Method::POST,
            paths::SYNC_PUSH.into(),
            Some(a.access.clone()),
            json!({"vault_id": vault.id, "device_id": a.device.id, "mutations": [put(ObjectId::new(), 0), delete(ObjectId::new(), 3)]}),
        ),
        (
            Method::POST,
            paths::fill(paths::VAULT_ENVELOPES, &[("vault_id", &v)]),
            Some(a.access.clone()),
            json!({"vault_access_key": vault.vak_bytes(), "envelope": device_envelope(a.device.id)}),
        ),
        (
            Method::POST,
            device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(a.access.clone()),
            approve_body(&a.device, request_id, &b.device, &[vault.id], now_unix()),
        ),
        (
            Method::POST,
            device_path(paths::DEVICE_ATTEST, b.device.id),
            Some(b.access.clone()),
            json!({"vault_id": vault.id, "vault_access_key": vault.vak_bytes(), "envelope": device_envelope(b.device.id)}),
        ),
        (
            Method::POST,
            paths::RECOVERY_VAULT_PASSWORD_REPLACE.into(),
            Some(a.access.clone()),
            json!({"vault_id": vault.id, "vault_access_key": vault.vak_bytes(), "envelope": password_envelope()}),
        ),
        (
            Method::PATCH,
            device_path(paths::DEVICE, b.device.id),
            Some(a.access.clone()),
            json!({"name": "renamed"}),
        ),
        (
            Method::POST,
            paths::DEVICES.into(),
            Some(b.access.clone()),
            json!({"vault_ids": [vault.id]}),
        ),
    ];

    for (method, path, token, valid) in &samples {
        for i in 0..iterations {
            let mut body = valid.clone();
            for _ in 0..=rng.below(3) {
                mutate(&mut body, &mut rng);
            }
            let bytes = serde_json::to_vec(&body).unwrap();
            let (status, resp) = send(&srv, method.clone(), path, token.as_deref(), bytes).await;
            check(status, &resp, &format!("{method} {path} #{i}"));
        }
        // Raw garbage too.
        let garbage: Vec<u8> = (0..rng.below(4096)).map(|_| rng.next() as u8).collect();
        let (status, resp) = send(&srv, method.clone(), path, token.as_deref(), garbage).await;
        check(status, &resp, &format!("{method} {path} garbage"));
    }

    // Query-string fuzzing of the pull endpoints.
    for i in 0..iterations * 4 {
        let after = match rng.below(5) {
            0 => "-9223372036854775808".to_owned(),
            1 => "99999999999999999999".to_owned(),
            2 => "abc".to_owned(),
            3 => String::new(),
            _ => (rng.next() % 1000).to_string(),
        };
        let limit = match rng.below(4) {
            0 => "0".to_owned(),
            1 => "4294967296".to_owned(),
            2 => "-5".to_owned(),
            _ => (rng.next() % 2000).to_string(),
        };
        for path in [
            format!(
                "{}?vault_id={v}&after={after}&limit={limit}",
                paths::SYNC_CHANGES
            ),
            format!(
                "{}?vault_id={v}&cursor={after}&limit={limit}",
                paths::SYNC_SNAPSHOT
            ),
        ] {
            let (status, resp) = send(&srv, Method::GET, &path, Some(&a.access), vec![]).await;
            check(status, &resp, &format!("GET {path} #{i}"));
        }
    }

    // The server is still healthy and the vault intact.
    assert_eq!(srv.changes(&a, vault.id, 0).await.0, StatusCode::OK);
}
