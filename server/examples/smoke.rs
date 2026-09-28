// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! End-to-end smoke test against a running server (docker-compose, k3s, …):
//!
//!   cargo run --example smoke -- http://127.0.0.1:8080
//!
//! register → create vault → push ciphertext → second device logs in →
//! untrusted pull is refused → trust request → Ed25519-signed approval →
//! pull the same ciphertext → realtime `vault_changed` → refresh → logout.
//!
//! Uses throwaway random identities (`smoke-…@example.test`); envelopes and
//! objects are random bytes of the right shape — the server cannot tell,
//! because it never decrypts anything. Exits non-zero on the first failure.

use anyhow::{bail, ensure, Context as _};
use cc_protocol::auth::AuthResponse;
use cc_protocol::devices::DeviceRegistration;
use cc_protocol::envelopes::{
    EnvelopeAlgorithm, EnvelopeKind, EnvelopeMetadata, KdfAlgorithm, KdfParams, NewEnvelope,
    RecipientType,
};
use cc_protocol::events::ServerEvent;
use cc_protocol::sync::{ChangesResponse, EncryptedBody, Mutation, MutationOp, OBJECT_FORMAT_V1};
use cc_protocol::version::Platform;
use cc_protocol::{paths, Bytes, DeviceId, MutationId, ObjectId, VaultId};
use consolecrypt_server::crypto::random_bytes;
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::StreamExt as _;
use reqwest::StatusCode;
use serde_json::{json, Value};

struct Device {
    id: DeviceId,
    signing: SigningKey,
    enc: [u8; 32],
}

impl Device {
    fn new() -> Self {
        Self {
            id: DeviceId::new(),
            signing: SigningKey::from_bytes(&random_bytes::<32>()),
            enc: random_bytes::<32>(),
        }
    }
    /// Proof of possession of the signing key (protocol 1.4, ADR-0006).
    fn proof(&self) -> Value {
        let issued_at = chrono::Utc::now().timestamp();
        let nonce = random_bytes::<32>();
        let msg = cc_protocol::canonical::device_login_message(self.id, issued_at, &nonce);
        json!({
            "issued_at": issued_at,
            "nonce": Bytes::new(nonce.to_vec()),
            "signature": Bytes::new(self.signing.sign(&msg).to_bytes().to_vec()),
        })
    }

    fn registration(&self, name: &str) -> DeviceRegistration {
        DeviceRegistration {
            device_id: self.id,
            name: name.into(),
            platform: Platform::Cli,
            encryption_public_key: Bytes::new(self.enc.to_vec()),
            signing_public_key: Bytes::new(self.signing.verifying_key().to_bytes().to_vec()),
            client_version: Some(concat!("smoke-", env!("CARGO_PKG_VERSION")).into()),
        }
    }
}

fn b(n: usize) -> Bytes {
    let mut v = vec![0u8; n];
    for c in v.chunks_mut(32) {
        c.copy_from_slice(&random_bytes::<32>()[..c.len()]);
    }
    Bytes::new(v)
}

fn envelope(recipient_type: RecipientType, recipient: Option<DeviceId>) -> NewEnvelope {
    let (algorithm, kdf, epk) = match recipient_type {
        RecipientType::Password => (
            EnvelopeAlgorithm::Argon2idXchacha20poly1305V1,
            Some(KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                salt: b(16),
                memory_kib: 65536,
                iterations: 3,
                parallelism: 1,
            }),
            None,
        ),
        RecipientType::Recovery => (EnvelopeAlgorithm::HkdfSha256Xchacha20poly1305V1, None, None),
        _ => (
            EnvelopeAlgorithm::X25519HkdfSha256Xchacha20poly1305V1,
            None,
            Some(b(32)),
        ),
    };
    NewEnvelope {
        recipient_type,
        recipient_id: recipient.map(Into::into),
        kind: EnvelopeKind::VrkV1,
        metadata: EnvelopeMetadata {
            algorithm,
            kdf,
            ephemeral_public_key: epk,
        },
        ciphertext: b(48),
        nonce: b(24),
    }
}

struct Api {
    http: reqwest::Client,
    base: String,
    /// Access token → device (every authenticated request is signed with the
    /// device key, protocol 1.5).
    signers: std::sync::Mutex<std::collections::HashMap<String, (DeviceId, SigningKey)>>,
}

/// `x-cc-device-proof` value (protocol 1.5).
fn request_proof(device: &Device, method: &str, path_and_query: &str, body: &[u8]) -> String {
    use sha2::Digest as _;
    let nonce = random_bytes::<32>();
    let issued_at = chrono::Utc::now().timestamp();
    let body_hash: [u8; 32] = sha2::Sha256::digest(body).into();
    let msg = cc_protocol::canonical::request_proof_message(
        device.id,
        method,
        path_and_query,
        &body_hash,
        issued_at,
        &nonce,
    );
    cc_protocol::devices::RequestProof {
        issued_at,
        nonce,
        signature: device.signing.sign(&msg).to_bytes(),
    }
    .encode()
}

impl Api {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        let bytes = body
            .as_ref()
            .map(|b| serde_json::to_vec(b).expect("json"))
            .unwrap_or_default();
        let mut req = self
            .http
            .request(method.clone(), format!("{}{}", self.base, path))
            .header(
                cc_protocol::version::HEADER_PROTOCOL_VERSION,
                cc_protocol::PROTOCOL_VERSION.to_string(),
            );
        if let Some(t) = token {
            req = req.bearer_auth(t);
            let signer = self.signers.lock().expect("lock").get(t).cloned();
            if let Some((id, signing)) = signer {
                let device = Device {
                    id,
                    signing,
                    enc: [0; 32],
                };
                req = req.header(
                    cc_protocol::version::HEADER_DEVICE_PROOF,
                    request_proof(&device, method.as_str(), path, &bytes),
                );
            }
        }
        if body.is_some() {
            req = req.header("content-type", "application/json").body(bytes);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("request {path}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn next_event(ws: &mut Ws) -> anyhow::Result<ServerEvent> {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .context("timed out waiting for an event")?;
        match msg {
            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) => {
                return Ok(serde_json::from_str::<ServerEvent>(t.as_str())?)
            }
            Some(Ok(_)) => continue,
            other => bail!("websocket ended: {other:?}"),
        }
    }
}

fn step(name: &str) {
    eprintln!("  ✓ {name}");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8080".into())
        .trim_end_matches('/')
        .to_owned();
    let api = Api {
        http: reqwest::Client::new(),
        base: base.clone(),
        signers: Default::default(),
    };
    let sign_as = |token: &str, device: &Device| {
        api.signers
            .lock()
            .expect("lock")
            .insert(token.to_owned(), (device.id, device.signing.clone()));
    };
    eprintln!("smoke test against {base}");
    use reqwest::Method as M;

    let (s, meta) = api.call(M::GET, paths::META, None, None).await?;
    ensure!(s == StatusCode::OK, "meta: {s}");
    step(&format!(
        "meta: server {} protocol {}",
        meta["server_version"], meta["protocol_version"]
    ));

    let email = format!("smoke-{}@example.test", uuid::Uuid::now_v7().simple());
    let password = format!("smoke-{}", uuid::Uuid::new_v4().simple());
    let dev_a = Device::new();
    let (s, body) = api
        .call(M::POST, paths::AUTH_REGISTER, None, Some(json!({"email": email, "password": password, "device": dev_a.registration("smoke A"), "device_proof": dev_a.proof()})))
        .await?;
    ensure!(s == StatusCode::CREATED, "register: {s} {body}");
    let a: AuthResponse = serde_json::from_value(body)?;
    let a_token = a.tokens.access_token.expose_secret().to_owned();
    sign_as(&a_token, &dev_a);
    step("register device A");

    let vault_id = VaultId::new();
    let vak = random_bytes::<32>();
    let (s, body) = api
        .call(
            M::POST,
            paths::VAULTS,
            Some(&a_token),
            Some(json!({
                "vault_id": vault_id,
                "vault_access_key": Bytes::new(vak.to_vec()),
                "password_envelope": envelope(RecipientType::Password, None),
                "recovery_envelope": envelope(RecipientType::Recovery, None),
                "device_envelope": envelope(RecipientType::Device, Some(dev_a.id)),
            })),
        )
        .await?;
    ensure!(s == StatusCode::CREATED, "create vault: {s} {body}");
    step("create vault");

    let body_1 = EncryptedBody {
        format: OBJECT_FORMAT_V1,
        ciphertext: b(512),
        nonce: b(24),
        wrapped_dek: b(48),
        wrapped_dek_nonce: b(24),
    };
    let object_id = ObjectId::new();
    let push = |token: String, device: DeviceId, mutation: Mutation| {
        let api = &api;
        async move {
            api.call(
                M::POST,
                paths::SYNC_PUSH,
                Some(&token),
                Some(json!({
                    "vault_id": vault_id, "device_id": device, "mutations": [mutation],
                })),
            )
            .await
        }
    };
    let (s, body) = push(
        a_token.clone(),
        dev_a.id,
        Mutation {
            mutation_id: MutationId::new(),
            object_id,
            base_revision: 0,
            op: MutationOp::Put {
                body: body_1.clone(),
            },
        },
    )
    .await?;
    ensure!(s == StatusCode::OK, "push: {s} {body}");
    step("push encrypted object");

    let dev_b = Device::new();
    let (s, body) = api
        .call(M::POST, paths::AUTH_LOGIN, None, Some(json!({"email": email, "password": password, "device": dev_b.registration("smoke B"), "device_proof": dev_b.proof()})))
        .await?;
    ensure!(s == StatusCode::OK, "login B: {s} {body}");
    let b_auth: AuthResponse = serde_json::from_value(body)?;
    let b_token = b_auth.tokens.access_token.expose_secret().to_owned();
    sign_as(&b_token, &dev_b);
    step("login device B");

    let changes_path = format!("{}?vault_id={vault_id}&after=0", paths::SYNC_CHANGES);
    let (s, _) = api
        .call(M::GET, &changes_path, Some(&b_token), None)
        .await?;
    ensure!(
        s == StatusCode::FORBIDDEN,
        "untrusted pull must be refused, got {s}"
    );
    step("untrusted device B cannot pull");

    let (s, req) = api
        .call(M::POST, paths::DEVICES, Some(&b_token), Some(json!({})))
        .await?;
    ensure!(s == StatusCode::CREATED, "trust request: {s} {req}");
    let request_id: cc_protocol::DeviceRequestId =
        serde_json::from_value(req["request_id"].clone())?;
    let issued_at = chrono::Utc::now().timestamp();
    let message = cc_protocol::canonical::device_approval_message(
        request_id,
        dev_a.id,
        dev_b.id,
        &dev_b.enc,
        &dev_b.signing.verifying_key().to_bytes(),
        issued_at,
        &[vault_id],
    );
    let signature = dev_a.signing.sign(&message).to_bytes();
    let approve = paths::fill(
        paths::DEVICE_APPROVE,
        &[("device_id", &dev_b.id.to_string())],
    );
    let (s, body) = api
        .call(M::POST, &approve, Some(&a_token), Some(json!({
            "request_id": request_id,
            "issued_at": issued_at,
            "signature": Bytes::new(signature.to_vec()),
            "envelopes": [{"vault_id": vault_id, "envelope": envelope(RecipientType::Device, Some(dev_b.id))}],
        })))
        .await?;
    ensure!(s == StatusCode::OK, "approve: {s} {body}");
    step("trust request + Ed25519-signed approval");

    let (s, body) = api
        .call(M::GET, &changes_path, Some(&b_token), None)
        .await?;
    ensure!(s == StatusCode::OK, "pull B: {s} {body}");
    let changes: ChangesResponse = serde_json::from_value(body)?;
    ensure!(
        changes.changes.len() == 1 && changes.changes[0].body.as_ref() == Some(&body_1),
        "pulled ciphertext differs"
    );
    step("device B pulls identical ciphertext");

    // Realtime: B listens, A pushes an update.
    let mut ws_req = format!("{}{}", base.replacen("http", "ws", 1), paths::EVENTS_WS);
    if !ws_req.starts_with("ws") {
        ws_req = format!("ws://{ws_req}");
    }
    let mut req =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(ws_req)?;
    req.headers_mut()
        .insert("authorization", format!("Bearer {b_token}").parse()?);
    req.headers_mut().insert(
        cc_protocol::version::HEADER_DEVICE_PROOF,
        request_proof(&dev_b, "GET", paths::EVENTS_WS, b"").parse()?,
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .context("websocket")?;
    ensure!(
        matches!(next_event(&mut ws).await?, ServerEvent::Hello { .. }),
        "expected hello"
    );
    let (s, _) = push(
        a_token.clone(),
        dev_a.id,
        Mutation {
            mutation_id: MutationId::new(),
            object_id,
            base_revision: 1,
            op: MutationOp::Put {
                body: body_1.clone(),
            },
        },
    )
    .await?;
    ensure!(s == StatusCode::OK, "second push: {s}");
    match next_event(&mut ws).await? {
        ServerEvent::VaultChanged {
            latest_sequence: 2, ..
        } => {}
        other => bail!("expected vault_changed(2), got {other:?}"),
    }
    step("realtime vault_changed over WebSocket");

    // Refresh is bound to the device key too (no bearer token: sign directly).
    let refresh_body =
        serde_json::to_vec(&json!({"refresh_token": b_auth.tokens.refresh_token.expose_secret()}))?;
    let resp = api
        .http
        .post(format!("{base}{}", paths::AUTH_REFRESH))
        .header(
            cc_protocol::version::HEADER_DEVICE_PROOF,
            request_proof(&dev_b, "POST", paths::AUTH_REFRESH, &refresh_body),
        )
        .header("content-type", "application/json")
        .body(refresh_body)
        .send()
        .await?;
    let s = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    ensure!(s == StatusCode::OK, "refresh: {s} {body}");
    let new_access = body["access_token"]
        .as_str()
        .context("access_token")?
        .to_owned();
    sign_as(&new_access, &dev_b);
    let (s, _) = api
        .call(M::POST, paths::AUTH_LOGOUT, Some(&new_access), None)
        .await?;
    ensure!(s == StatusCode::NO_CONTENT, "logout: {s}");
    step("refresh rotation + logout");

    eprintln!("smoke test passed");
    Ok(())
}
