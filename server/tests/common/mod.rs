// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Integration-test harness: every test gets a fresh PostgreSQL database
//! (created from `CC_TEST_DATABASE_URL`, dropped afterwards) and a real server
//! on a random local port. Keys, tokens and passwords are generated at run
//! time; nothing secret is stored in the repository.
//!
//! Without `CC_TEST_DATABASE_URL` the DB tests are skipped with a notice,
//! unless `CC_TEST_REQUIRE_DB=1` (CI), in which case they fail.

#![allow(dead_code)]

pub mod enrollment;
pub mod sharing;

use cc_protocol::auth::{AuthResponse, SecretString};
use cc_protocol::devices::DeviceRegistration;
use cc_protocol::envelopes::{
    EnvelopeAlgorithm, EnvelopeKind, EnvelopeMetadata, KdfAlgorithm, KdfParams, NewEnvelope,
    RecipientType,
};
use cc_protocol::sync::{EncryptedBody, Mutation, MutationOp, OBJECT_FORMAT_V1};
use cc_protocol::vaults::CreateVaultRequest;
use cc_protocol::version::Platform;
use cc_protocol::{Bytes, DeviceId, MutationId, ObjectId, VaultId};
use consolecrypt_server::config::EventBusKind;
use consolecrypt_server::mail::{MailKind, MailMessage, Mailer};
use consolecrypt_server::{build_router, db, AppState, Config};
use ed25519_dalek::SigningKey;
use futures_util::future::BoxFuture;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::Value;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub fn random<const N: usize>() -> [u8; N] {
    consolecrypt_server::crypto::random_bytes::<N>()
}

/// Random printable password (never a literal in the repo).
pub fn random_password() -> String {
    use base64::Engine as _;
    format!(
        "pw-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random::<18>())
    )
}

pub fn random_email() -> String {
    format!("user-{}@example.test", uuid::Uuid::now_v7().simple())
}

/// Captures outgoing mail so tests can read single-use tokens.
#[derive(Debug, Default)]
pub struct CapturingMailer {
    pub messages: Mutex<Vec<(MailKind, String, String)>>,
}

impl Mailer for CapturingMailer {
    fn send(&self, msg: MailMessage) -> BoxFuture<'_, anyhow::Result<()>> {
        self.messages
            .lock()
            .unwrap()
            .push((msg.kind, msg.to.clone(), msg.body.clone()));
        Box::pin(async { Ok(()) })
    }
    fn delivers(&self) -> bool {
        true
    }
}

impl CapturingMailer {
    /// Latest `cct_…` token mailed to `to` with `kind`.
    pub fn token_for(&self, to: &str, kind: MailKind) -> Option<String> {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(k, t, _)| *k == kind && t == to)
            .and_then(|(_, _, body)| {
                body.split_whitespace()
                    .find(|w| w.starts_with("cct_"))
                    .map(str::to_owned)
            })
    }

    pub fn count(&self, kind: MailKind) -> usize {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _, _)| *k == kind)
            .count()
    }
}

pub struct TestServer {
    pub base: String,
    pub ws_base: String,
    pub state: AppState,
    pub http: reqwest::Client,
    pub mailer: Arc<CapturingMailer>,
    /// Access token → device key: requests with a registered token are
    /// signed automatically (protocol 1.5 request proofs).
    signers: Mutex<std::collections::HashMap<String, (DeviceId, SigningKey)>>,
    _db: TestDb,
}

/// A fresh, empty database (no migrations), dropped on `Drop`.
pub struct TestDb {
    pub pool: sqlx::PgPool,
    admin_opts: PgConnectOptions,
    pub db_name: String,
}

impl TestDb {
    /// `None` (skip) when no test database is configured.
    pub async fn create() -> Option<(TestDb, String)> {
        let url = test_db_url()?;
        let admin_opts = PgConnectOptions::from_str(&url).expect("valid CC_TEST_DATABASE_URL");
        let db_name = format!("cc_test_{}", uuid::Uuid::now_v7().simple());
        let mut admin = PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect to test PostgreSQL");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}")))
            .execute(&mut admin)
            .await
            .expect("create test database");
        admin.close().await.ok();
        let pool = db::connect_with(admin_opts.clone().database(&db_name), 10)
            .await
            .expect("connect test database");
        Some((
            TestDb {
                pool,
                admin_opts,
                db_name,
            },
            url,
        ))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let opts = self.admin_opts.clone();
        let name = self.db_name.clone();
        // Separate runtime: the test runtime may already be shutting down.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Ok(mut c) = PgConnection::connect_with(&opts).await {
                    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                    )))
                    .execute(&mut c)
                    .await;
                }
            });
        })
        .join();
    }
}

fn test_db_url() -> Option<String> {
    match std::env::var("CC_TEST_DATABASE_URL") {
        Ok(u) if !u.trim().is_empty() => Some(u),
        _ => {
            if std::env::var("CC_TEST_REQUIRE_DB").is_ok_and(|v| v == "1") {
                panic!("CC_TEST_REQUIRE_DB=1 but CC_TEST_DATABASE_URL is not set");
            }
            eprintln!("skipping DB test: set CC_TEST_DATABASE_URL (see server/README.md)");
            None
        }
    }
}

/// Evaluate to a running [`TestServer`] or return from the test (skip).
#[macro_export]
macro_rules! server {
    () => {
        match common::TestServer::spawn(|_| {}).await {
            Some(s) => s,
            None => return,
        }
    };
    ($f:expr) => {
        match common::TestServer::spawn($f).await {
            Some(s) => s,
            None => return,
        }
    };
}

impl TestServer {
    pub async fn spawn(configure: impl FnOnce(&mut Config)) -> Option<TestServer> {
        let (test_db, url) = TestDb::create().await?;
        Some(Self::spawn_on(test_db, url, configure).await)
    }

    /// Run a server on an existing test database (migrations are applied).
    pub async fn spawn_on(
        test_db: TestDb,
        url: String,
        configure: impl FnOnce(&mut Config),
    ) -> TestServer {
        let pool = test_db.pool.clone();
        db::migrate(&pool).await.expect("migrations");

        let mut config = Config::for_tests(url);
        config.event_bus = EventBusKind::Postgres;
        configure(&mut config);
        let mailer = Arc::new(CapturingMailer::default());
        let state = AppState::with_mailer(config, pool, mailer.clone())
            .await
            .expect("state");
        let app = build_router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .ok();
        });
        TestServer {
            base: format!("http://{addr}"),
            ws_base: format!("ws://{addr}"),
            state,
            http: reqwest::Client::new(),
            mailer,
            signers: Mutex::default(),
            _db: test_db,
        }
    }

    /// Sign future requests carrying `token` with `device`'s key.
    pub fn register_signer(&self, token: &str, device: &TestDevice) {
        self.signers
            .lock()
            .unwrap()
            .insert(token.to_owned(), (device.id, device.signing.clone()));
    }

    fn alias_signer(&self, existing: &str, new: &str) {
        let mut signers = self.signers.lock().unwrap();
        if let Some(entry) = signers.get(existing).cloned() {
            signers.insert(new.to_owned(), entry);
        }
    }

    /// `x-cc-device-proof` value for a request signed by `token`'s device,
    /// if that token is registered.
    pub fn proof_for(
        &self,
        token: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Option<String> {
        let signers = self.signers.lock().unwrap();
        let (device_id, key) = signers.get(token)?;
        Some(request_proof(
            *device_id,
            key,
            method,
            path_and_query,
            body,
            chrono::Utc::now().timestamp(),
        ))
    }

    pub fn db_name(&self) -> &str {
        &self._db.db_name
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Raw request; returns status + JSON body (Null if empty/non-JSON).
    pub async fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> (StatusCode, Value) {
        let bytes = body
            .map(|b| serde_json::to_vec(b).unwrap())
            .unwrap_or_default();
        let mut req = self.http.request(method.clone(), self.url(path));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        // Refresh carries no bearer token: it is signed by the device of the
        // (registered) refresh token in the body.
        let refresh_token = (path == cc_protocol::paths::AUTH_REFRESH)
            .then(|| {
                serde_json::from_slice::<Value>(&bytes)
                    .ok()
                    .and_then(|v| v["refresh_token"].as_str().map(str::to_owned))
            })
            .flatten();
        let signer = token.map(str::to_owned).or(refresh_token);
        if let Some(t) = &signer {
            if let Some(proof) = self.proof_for(t, method.as_str(), path, &bytes) {
                req = req.header(cc_protocol::version::HEADER_DEVICE_PROOF, proof);
            }
        }
        if body.is_some() {
            req = req.header("content-type", "application/json").body(bytes);
        }
        let resp = req.send().await.expect("request");
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        // A successful refresh hands out new tokens of the same device.
        if path == cc_protocol::paths::AUTH_REFRESH && status.is_success() {
            if let (Some(old), Some(access), Some(refresh)) = (
                signer.as_deref(),
                value["access_token"].as_str(),
                value["refresh_token"].as_str(),
            ) {
                self.alias_signer(old, access);
                self.alias_signer(old, refresh);
            }
        }
        (status, value)
    }

    /// Add `x-cc-device-proof` for `token`'s device to a raw request.
    pub fn signed(
        &self,
        req: reqwest::RequestBuilder,
        token: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> reqwest::RequestBuilder {
        match self.proof_for(token, method, path_and_query, body) {
            Some(p) => req.header(cc_protocol::version::HEADER_DEVICE_PROOF, p),
            None => req,
        }
    }

    /// A session from an `AuthResponse`, with its tokens registered for signing.
    pub fn session(
        &self,
        email: String,
        password: String,
        device: TestDevice,
        body: Value,
    ) -> Session {
        let s = Session::from_auth(email, password, device, body);
        self.register_signer(&s.access, &s.device);
        self.register_signer(&s.refresh, &s.device);
        s
    }

    pub async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.request::<()>(Method::GET, path, Some(token), None)
            .await
    }

    pub async fn post<B: Serialize + ?Sized>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> (StatusCode, Value) {
        self.request(Method::POST, path, token, Some(body)).await
    }

    pub async fn delete<B: Serialize + ?Sized>(
        &self,
        path: &str,
        token: &str,
        body: Option<&B>,
    ) -> (StatusCode, Value) {
        self.request(Method::DELETE, path, Some(token), body).await
    }

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        device: &TestDevice,
    ) -> (StatusCode, Value) {
        self.post(
            cc_protocol::paths::AUTH_REGISTER,
            None,
            &serde_json::json!({
                "email": email,
                "password": password,
                "device": device.registration(),
                "device_proof": device.proof(),
            }),
        )
        .await
    }

    /// Login with a valid device proof (protocol 1.4).
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        device: &TestDevice,
    ) -> (StatusCode, Value) {
        self.login_with_proof(email, password, device, Some(device.proof()))
            .await
    }

    /// Login with an arbitrary (or no) device proof.
    pub async fn login_with_proof(
        &self,
        email: &str,
        password: &str,
        device: &TestDevice,
        proof: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut body = serde_json::json!({
            "email": email,
            "password": password,
            "device": device.registration(),
        });
        if let Some(p) = proof {
            body["device_proof"] = p;
        }
        self.post(cc_protocol::paths::AUTH_LOGIN, None, &body).await
    }

    /// Register a fresh account with a fresh device.
    pub async fn new_account(&self) -> Session {
        let email = random_email();
        let password = random_password();
        let device = TestDevice::new("Device A");
        let (status, body) = self.register(&email, &password, &device).await;
        assert_eq!(status, StatusCode::CREATED, "register: {body}");
        self.session(email, password, device, body)
    }

    /// Log the account in from a new device.
    pub async fn new_device_session(&self, account: &Session, name: &str) -> Session {
        let device = TestDevice::new(name);
        let (status, body) = self.login(&account.email, &account.password, &device).await;
        assert_eq!(status, StatusCode::OK, "login: {body}");
        self.session(
            account.email.clone(),
            account.password.clone(),
            device,
            body,
        )
    }

    /// Create a vault owned by `s` (its device becomes trusted).
    pub async fn create_vault(&self, s: &Session) -> TestVault {
        let vault = TestVault::new();
        let (status, body) = self
            .post(
                cc_protocol::paths::VAULTS,
                Some(&s.access),
                &vault.create_request(s.device.id),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "create vault: {body}");
        vault
    }

    pub async fn push(
        &self,
        s: &Session,
        vault: VaultId,
        mutations: Vec<Mutation>,
    ) -> (StatusCode, Value) {
        self.post(
            cc_protocol::paths::SYNC_PUSH,
            Some(&s.access),
            &serde_json::json!({
                "vault_id": vault,
                "device_id": s.device.id,
                "mutations": mutations,
            }),
        )
        .await
    }

    pub async fn changes(&self, s: &Session, vault: VaultId, after: i64) -> (StatusCode, Value) {
        self.get(
            &format!(
                "{}?vault_id={vault}&after={after}",
                cc_protocol::paths::SYNC_CHANGES
            ),
            &s.access,
        )
        .await
    }

    /// Attest `s`'s device for `vault` with the vault access key.
    pub async fn attest(&self, s: &Session, vault: &TestVault) -> (StatusCode, Value) {
        self.post(
            &cc_protocol::paths::fill(
                cc_protocol::paths::DEVICE_ATTEST,
                &[("device_id", &s.device.id.to_string())],
            ),
            Some(&s.access),
            &serde_json::json!({
                "vault_id": vault.id,
                "vault_access_key": Bytes::new(vault.vak.to_vec()),
                "envelope": device_envelope(s.device.id),
            }),
        )
        .await
    }

    pub async fn db_scalar_i64(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.state.db)
            .await
            .expect("scalar query")
    }
}

/// A simulated client installation with runtime-generated keys.
pub struct TestDevice {
    pub id: DeviceId,
    pub name: String,
    pub signing: SigningKey,
    pub encryption_public_key: [u8; 32],
}

impl TestDevice {
    pub fn new(name: &str) -> Self {
        Self {
            id: DeviceId::new(),
            name: name.to_owned(),
            signing: SigningKey::from_bytes(&random::<32>()),
            encryption_public_key: random::<32>(),
        }
    }

    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// A fresh device proof of possession (ADR-0006).
    pub fn proof(&self) -> Value {
        self.proof_at(chrono::Utc::now().timestamp(), random::<32>())
    }

    pub fn proof_at(&self, issued_at: i64, nonce: [u8; 32]) -> Value {
        use ed25519_dalek::Signer as _;
        let msg = cc_protocol::canonical::device_login_message(self.id, issued_at, &nonce);
        serde_json::json!({
            "issued_at": issued_at,
            "nonce": Bytes::new(nonce.to_vec()),
            "signature": Bytes::new(self.signing.sign(&msg).to_bytes().to_vec()),
        })
    }

    pub fn registration(&self) -> DeviceRegistration {
        DeviceRegistration {
            device_id: self.id,
            name: self.name.clone(),
            platform: Platform::Cli,
            encryption_public_key: Bytes::new(self.encryption_public_key.to_vec()),
            signing_public_key: Bytes::new(self.signing_public_key().to_vec()),
            client_version: Some("0.0.0-test".into()),
        }
    }
}

pub struct Session {
    pub email: String,
    pub password: String,
    pub device: TestDevice,
    pub user_id: cc_protocol::UserId,
    pub session_id: cc_protocol::SessionId,
    pub access: String,
    pub refresh: String,
}

impl Session {
    pub fn from_auth(email: String, password: String, device: TestDevice, body: Value) -> Self {
        let auth: AuthResponse = serde_json::from_value(body).expect("AuthResponse");
        assert_eq!(auth.device_id, device.id);
        Session {
            email,
            password,
            device,
            user_id: auth.user_id,
            session_id: auth.tokens.session_id,
            access: auth.tokens.access_token.expose_secret().to_owned(),
            refresh: auth.tokens.refresh_token.expose_secret().to_owned(),
        }
    }
}

pub struct TestVault {
    pub id: VaultId,
    pub vak: [u8; 32],
}

impl TestVault {
    pub fn new() -> Self {
        Self {
            id: VaultId::new(),
            vak: random::<32>(),
        }
    }

    pub fn vak_bytes(&self) -> Bytes {
        Bytes::new(self.vak.to_vec())
    }

    pub fn create_request(&self, device: DeviceId) -> CreateVaultRequest {
        CreateVaultRequest {
            vault_id: self.id,
            vault_access_key: self.vak_bytes(),
            password_envelope: password_envelope(),
            recovery_envelope: recovery_envelope(),
            device_envelope: device_envelope(device),
        }
    }
}

/// Envelopes with random "ciphertext" of the right shape: the server cannot
/// and does not decrypt them.
pub fn password_envelope() -> NewEnvelope {
    NewEnvelope {
        recipient_type: RecipientType::Password,
        recipient_id: None,
        kind: EnvelopeKind::VrkV1,
        metadata: EnvelopeMetadata {
            algorithm: EnvelopeAlgorithm::Argon2idXchacha20poly1305V1,
            kdf: Some(KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                salt: Bytes::new(random::<16>().to_vec()),
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 1,
            }),
            ephemeral_public_key: None,
        },
        ciphertext: Bytes::new(random::<48>().to_vec()),
        nonce: Bytes::new(random::<24>().to_vec()),
    }
}

pub fn recovery_envelope() -> NewEnvelope {
    NewEnvelope {
        recipient_type: RecipientType::Recovery,
        recipient_id: None,
        kind: EnvelopeKind::VrkV1,
        metadata: EnvelopeMetadata {
            algorithm: EnvelopeAlgorithm::HkdfSha256Xchacha20poly1305V1,
            kdf: None,
            ephemeral_public_key: None,
        },
        ciphertext: Bytes::new(random::<48>().to_vec()),
        nonce: Bytes::new(random::<24>().to_vec()),
    }
}

pub fn device_envelope(device: DeviceId) -> NewEnvelope {
    NewEnvelope {
        recipient_type: RecipientType::Device,
        recipient_id: Some(device.into()),
        kind: EnvelopeKind::VrkV1,
        metadata: EnvelopeMetadata {
            algorithm: EnvelopeAlgorithm::X25519HkdfSha256Xchacha20poly1305V1,
            kdf: None,
            ephemeral_public_key: Some(Bytes::new(random::<32>().to_vec())),
        },
        ciphertext: Bytes::new(random::<48>().to_vec()),
        nonce: Bytes::new(random::<24>().to_vec()),
    }
}

pub fn body(len: usize) -> EncryptedBody {
    let mut ciphertext = vec![0u8; len];
    for chunk in ciphertext.chunks_mut(32) {
        let r = random::<32>();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    EncryptedBody {
        format: OBJECT_FORMAT_V1,
        ciphertext: Bytes::new(ciphertext),
        nonce: Bytes::new(random::<24>().to_vec()),
        wrapped_dek: Bytes::new(random::<48>().to_vec()),
        wrapped_dek_nonce: Bytes::new(random::<24>().to_vec()),
    }
}

pub fn put(object_id: ObjectId, base_revision: i64) -> Mutation {
    Mutation {
        mutation_id: MutationId::new(),
        object_id,
        base_revision,
        op: MutationOp::Put { body: body(256) },
    }
}

pub fn delete(object_id: ObjectId, base_revision: i64) -> Mutation {
    Mutation {
        mutation_id: MutationId::new(),
        object_id,
        base_revision,
        op: MutationOp::Delete,
    }
}

pub fn secret(s: &str) -> SecretString {
    SecretString::new(s)
}

// ------------------------------------------------------------ websockets --

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open `/v1/events/ws` with a bearer token. Err(status) if the upgrade fails.
pub async fn ws_connect(srv: &TestServer, token: &str) -> Result<Ws, u16> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    let mut req = format!("{}{}", srv.ws_base, cc_protocol::paths::EVENTS_WS)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    if let Some(proof) = srv.proof_for(token, "GET", cc_protocol::paths::EVENTS_WS, b"") {
        req.headers_mut().insert(
            cc_protocol::version::HEADER_DEVICE_PROOF,
            proof.parse().unwrap(),
        );
    }
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("ws connect: {e}"),
    }
}

#[derive(Debug)]
pub enum WsItem {
    Event(cc_protocol::events::ServerEvent),
    Closed(Option<u16>),
}

/// Next event or close frame (pings skipped), with a timeout.
pub async fn ws_next(ws: &mut Ws) -> WsItem {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;
    let deadline = std::time::Duration::from_secs(5);
    loop {
        let msg = tokio::time::timeout(deadline, ws.next())
            .await
            .expect("timed out waiting for a websocket message");
        match msg {
            Some(Ok(Message::Text(t))) => {
                return WsItem::Event(serde_json::from_str(t.as_str()).expect("event json"))
            }
            Some(Ok(Message::Close(frame))) => {
                return WsItem::Closed(frame.map(|f| u16::from(f.code)))
            }
            Some(Ok(_)) => continue,
            Some(Err(_)) | None => return WsItem::Closed(None),
        }
    }
}

pub async fn ws_event(ws: &mut Ws) -> cc_protocol::events::ServerEvent {
    match ws_next(ws).await {
        WsItem::Event(e) => e,
        other => panic!("expected event, got {other:?}"),
    }
}

/// Assert nothing arrives within `ms` milliseconds.
pub async fn ws_silent(ws: &mut Ws, ms: u64) {
    use futures_util::StreamExt as _;
    let r = tokio::time::timeout(std::time::Duration::from_millis(ms), ws.next()).await;
    if let Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t)))) = r {
        panic!("unexpected event: {t}");
    }
}

// --------------------------------------------------------- device trust --

/// JSON body of `POST /v1/devices/{new}/approve`, signed by `approver`.
pub fn approve_body(
    approver: &TestDevice,
    request_id: cc_protocol::DeviceRequestId,
    new_device: &TestDevice,
    vaults: &[VaultId],
    issued_at: i64,
) -> Value {
    use ed25519_dalek::Signer as _;
    let msg = cc_protocol::canonical::device_approval_message(
        request_id,
        approver.id,
        new_device.id,
        &new_device.encryption_public_key,
        &new_device.signing_public_key(),
        issued_at,
        vaults,
    );
    let signature = approver.signing.sign(&msg).to_bytes();
    serde_json::json!({
        "request_id": request_id,
        "issued_at": issued_at,
        "signature": Bytes::new(signature.to_vec()),
        "envelopes": vaults.iter().map(|v| serde_json::json!({
            "vault_id": v,
            "envelope": device_envelope(new_device.id),
        })).collect::<Vec<_>>(),
    })
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn device_path(template: &str, device: DeviceId) -> String {
    cc_protocol::paths::fill(template, &[("device_id", &device.to_string())])
}

/// Build an `x-cc-device-proof` header value (protocol 1.5).
pub fn request_proof(
    device_id: DeviceId,
    key: &SigningKey,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    issued_at: i64,
) -> String {
    use ed25519_dalek::Signer as _;
    let nonce = random::<32>();
    let body_hash = consolecrypt_server::crypto::sha256(body);
    let msg = cc_protocol::canonical::request_proof_message(
        device_id,
        method,
        path_and_query,
        &body_hash,
        issued_at,
        &nonce,
    );
    cc_protocol::devices::RequestProof {
        issued_at,
        nonce,
        signature: key.sign(&msg).to_bytes(),
    }
    .encode()
}
