// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Enterprise sign-in test helpers (protocol 1.8): an in-process mock OIDC
//! IdP (ES256 keys generated at run time) and the app/browser side of the
//! OIDC flow. Secrets written for the server are random per test and live in
//! a private temporary directory.

use super::{random, TestDevice, TestServer};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cc_protocol::enterprise_auth::{OidcAppCallback, OidcStartQuery};
use consolecrypt_server::config::{
    AuthConfig, AuthModeKind, OidcConfig, OidcPreset, ProviderKind, TokenAuthMethod,
};
use consolecrypt_server::Config;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn s256(verifier: &str) -> String {
    b64(&consolecrypt_server::crypto::sha256(verifier.as_bytes()))
}

/// A private temporary directory removed on drop.
#[derive(Debug)]
pub struct SecretDir(pub PathBuf);

impl SecretDir {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("cc-ent-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(dir)
    }

    pub fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }
}

impl Drop for SecretDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// How the mock IdP mangles the next ID token (negative tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tweak {
    None,
    ForeignIssuer,
    ForeignAudience,
    BadNonce,
    Expired,
    UnknownKid,
    AlgNone,
    Hs256,
    BadSignature,
}

/// The next person who "signs in" at the mock IdP.
#[derive(Debug, Clone)]
pub struct MockUser {
    pub sub: String,
    pub claims: Map<String, Value>,
}

impl MockUser {
    pub fn new(email: &str) -> Self {
        let mut claims = Map::new();
        claims.insert("email".into(), json!(email));
        claims.insert("email_verified".into(), json!(true));
        claims.insert("groups".into(), json!(["consolecrypt-users"]));
        Self {
            sub: format!("sub-{}", uuid::Uuid::now_v7().simple()),
            claims,
        }
    }
}

#[derive(Debug)]
struct Grant {
    user: MockUser,
    nonce: String,
    challenge: String,
    redirect_uri: String,
}

#[derive(Debug, Default)]
pub struct MockState {
    pub next_user: Option<MockUser>,
    pub tweak: Option<Tweak>,
    codes: HashMap<String, Grant>,
    refresh: HashMap<String, MockUser>,
    pub disabled: HashSet<String>,
    pub unavailable: bool,
    pub jwks_fetches: usize,
    pub refresh_grants: usize,
    /// Drop the groups claim on refreshed ID tokens (user left the group).
    pub drop_groups_on_refresh: bool,
}

pub struct MockIdp {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub state: Arc<Mutex<MockState>>,
    key: Arc<EcdsaKeyPair>,
}

#[derive(Clone)]
struct Ctx {
    issuer: String,
    client_id: String,
    client_secret: String,
    state: Arc<Mutex<MockState>>,
    key: Arc<EcdsaKeyPair>,
}

impl MockIdp {
    pub async fn start() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = Arc::new(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let ctx = Ctx {
            issuer: issuer.clone(),
            client_id: "consolecrypt-test".into(),
            client_secret: b64(&random::<24>()),
            state: Arc::default(),
            key,
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(ctx.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        Self {
            issuer,
            client_id: ctx.client_id,
            client_secret: ctx.client_secret,
            state: ctx.state,
            key: ctx.key,
        }
    }

    pub fn set_user(&self, user: &MockUser) {
        self.state.lock().unwrap().next_user = Some(user.clone());
    }

    pub fn set_tweak(&self, t: Tweak) {
        self.state.lock().unwrap().tweak = Some(t);
    }

    pub fn jwks_fetches(&self) -> usize {
        self.state.lock().unwrap().jwks_fetches
    }

    /// Server configuration for this IdP (`configure` closure body).
    pub fn configure(&self, dir: &SecretDir, c: &mut Config) {
        let secret = dir.write(
            "client-secret",
            format!("{}\n", self.client_secret).as_bytes(),
        );
        let key = dir.write("token-key", b64(&random::<32>()).as_bytes());
        let _ = &self.key;
        c.auth = AuthConfig {
            mode: AuthModeKind::Enterprise,
            provider: Some(ProviderKind::Oidc),
            display_name: Some("Acme SSO".into()),
            allowed_domains: vec!["acme.test".into()],
            oidc: Some(OidcConfig {
                preset: OidcPreset::Generic,
                issuer: self.issuer.clone(),
                client_id: self.client_id.clone(),
                client_secret_file: secret,
                scopes: vec!["openid".into(), "email".into(), "offline_access".into()],
                email_claim: "email".into(),
                required_claim: None,
                require_mfa: false,
                mfa_acr_values: vec![],
                token_key_file: key,
                token_auth_method: TokenAuthMethod::Basic,
                ca_file: None,
                extra_auth_params: vec![],
            }),
            ..AuthConfig::standard()
        };
        c.auth.mode = AuthModeKind::Enterprise;
    }
}

async fn discovery(State(c): State<Ctx>) -> Json<Value> {
    Json(json!({
        "issuer": c.issuer,
        "authorization_endpoint": format!("{}/authorize", c.issuer),
        "token_endpoint": format!("{}/token", c.issuer),
        "jwks_uri": format!("{}/jwks", c.issuer),
        "id_token_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks(State(c): State<Ctx>) -> Json<Value> {
    c.state.lock().unwrap().jwks_fetches += 1;
    let p = c.key.public_key().as_ref();
    Json(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "k1",
        "x": b64(&p[1..33]), "y": b64(&p[33..65]),
    }]}))
}

fn redirect(location: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, location.to_owned())]).into_response()
}

async fn authorize(State(c): State<Ctx>, Query(q): Query<HashMap<String, String>>) -> Response {
    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(q.get("client_id"), Some(&c.client_id));
    assert_eq!(
        q.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let mut st = c.state.lock().unwrap();
    let user = st.next_user.clone().expect("test set the next IdP user");
    let code = b64(&random::<16>());
    let redirect_uri = q["redirect_uri"].clone();
    st.codes.insert(
        code.clone(),
        Grant {
            user,
            nonce: q["nonce"].clone(),
            challenge: q["code_challenge"].clone(),
            redirect_uri: redirect_uri.clone(),
        },
    );
    let mut url = reqwest::Url::parse(&redirect_uri).unwrap();
    url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &q["state"]);
    redirect(url.as_str())
}

fn sign(c: &Ctx, header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig = c.key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64(sig.as_ref()))
}

fn id_token(c: &Ctx, user: &MockUser, nonce: Option<&str>, tweak: Tweak, groups: bool) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": c.issuer, "aud": c.client_id, "sub": user.sub, "iat": now, "exp": now + 300,
    });
    for (k, v) in &user.claims {
        if k == "groups" && !groups {
            continue;
        }
        claims[k] = v.clone();
    }
    if let Some(n) = nonce {
        claims["nonce"] = json!(n);
    }
    let mut header = json!({"alg": "ES256", "typ": "JWT", "kid": "k1"});
    match tweak {
        Tweak::None | Tweak::BadSignature => {}
        Tweak::ForeignIssuer => claims["iss"] = json!("https://evil.example"),
        Tweak::ForeignAudience => claims["aud"] = json!("someone-else"),
        Tweak::BadNonce => claims["nonce"] = json!("not-the-nonce"),
        Tweak::Expired => {
            claims["iat"] = json!(now - 3600);
            claims["exp"] = json!(now - 600);
        }
        Tweak::UnknownKid => header["kid"] = json!("rotated-away"),
        Tweak::AlgNone => {
            return format!(
                "{}.{}.",
                b64(json!({"alg": "none"}).to_string().as_bytes()),
                b64(claims.to_string().as_bytes())
            )
        }
        Tweak::Hs256 => {
            let h = b64(json!({"alg": "HS256", "kid": "k1"}).to_string().as_bytes());
            let p = b64(claims.to_string().as_bytes());
            let mac = ring::hmac::sign(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, c.client_secret.as_bytes()),
                format!("{h}.{p}").as_bytes(),
            );
            return format!("{h}.{p}.{}", b64(mac.as_ref()));
        }
    }
    let token = sign(c, &header, &claims);
    if tweak == Tweak::BadSignature {
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        claims["sub"] = json!("someone-else");
        parts[1] = b64(claims.to_string().as_bytes());
        return parts.join(".");
    }
    token
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

async fn token(
    State(c): State<Ctx>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", c.client_id, c.client_secret))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&expected)
    {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let mut st = c.state.lock().unwrap();
    if st.unavailable {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let refresh = b64(&random::<24>());
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some(grant) = st.codes.remove(&f["code"]) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if f.get("redirect_uri") != Some(&grant.redirect_uri)
                || f.get("code_verifier").map(|v| s256(v)) != Some(grant.challenge.clone())
            {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let tweak = st.tweak.take().unwrap_or(Tweak::None);
            let id = id_token(&c, &grant.user, Some(&grant.nonce), tweak, true);
            st.refresh.insert(refresh.clone(), grant.user);
            Json(json!({
                "access_token": "at", "token_type": "Bearer", "expires_in": 300,
                "id_token": id, "refresh_token": refresh,
            }))
            .into_response()
        }
        Some("refresh_token") => {
            st.refresh_grants += 1;
            let Some(user) = st.refresh.remove(&f["refresh_token"]) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if st.disabled.contains(&user.sub) {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let id = id_token(&c, &user, None, Tweak::None, !st.drop_groups_on_refresh);
            st.refresh.insert(refresh.clone(), user);
            Json(json!({
                "access_token": "at", "token_type": "Bearer", "expires_in": 300,
                "id_token": id, "refresh_token": refresh,
            }))
            .into_response()
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

/// The app side of one OIDC sign-in.
pub struct AppFlow {
    pub verifier: String,
    pub state: String,
    pub redirect_uri: String,
}

impl AppFlow {
    pub fn new() -> Self {
        Self {
            verifier: b64(&random::<32>()),
            state: b64(&random::<12>()),
            redirect_uri: "http://127.0.0.1:49152/auth/callback".into(),
        }
    }

    pub fn start_url(&self, srv: &TestServer, device: &TestDevice, hint: Option<&str>) -> String {
        OidcStartQuery {
            redirect_uri: self.redirect_uri.clone(),
            code_challenge: s256(&self.verifier),
            code_challenge_method: Some("S256".into()),
            state: self.state.clone(),
            device_id: device.id,
            login_hint: hint.map(str::to_owned),
        }
        .to_url(&srv.base)
    }
}

pub fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

pub fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .unwrap_or_else(|| panic!("expected a redirect, got {}", resp.status()))
        .to_str()
        .unwrap()
        .to_owned()
}

/// Parse the app redirect (`login_code` / `error`), checking its `state`.
pub fn app_callback(flow: &AppFlow, url: &str) -> OidcAppCallback {
    assert!(
        url.starts_with(&flow.redirect_uri),
        "redirect to the app expected, got {url}"
    );
    let parsed = reqwest::Url::parse(url).unwrap();
    let mut cb = OidcAppCallback::default();
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "login_code" => cb.login_code = Some(v.as_ref().into()),
            "state" => cb.state = v.into_owned(),
            "error" => cb.error = Some(v.into_owned()),
            "error_description" => cb.error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    assert_eq!(cb.state, flow.state, "state echoed back to the app");
    cb
}

/// Browser leg through the mock IdP: start → IdP → callback → app redirect.
pub async fn browser_via_mock(
    srv: &TestServer,
    flow: &AppFlow,
    device: &TestDevice,
) -> OidcAppCallback {
    let http = no_redirect_client();
    let r = http
        .get(flow.start_url(srv, device, None))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "start");
    let r = http.get(location(&r)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "idp authorize");
    let r = http.get(location(&r)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "callback");
    app_callback(flow, &location(&r))
}

/// `POST /v1/auth/oidc/exchange`.
pub async fn exchange(
    srv: &TestServer,
    login_code: &str,
    verifier: &str,
    device: &TestDevice,
) -> (StatusCode, Value) {
    srv.post(
        cc_protocol::paths::AUTH_OIDC_EXCHANGE,
        None,
        &json!({
            "login_code": login_code,
            "code_verifier": verifier,
            "device": device.registration(),
            "device_proof": device.proof(),
        }),
    )
    .await
}

/// Full mock sign-in of `user` on `device`; returns the exchange response.
pub async fn mock_login(
    srv: &TestServer,
    idp: &MockIdp,
    user: &MockUser,
    device: &TestDevice,
) -> (StatusCode, Value) {
    idp.set_user(user);
    let flow = AppFlow::new();
    let cb = browser_via_mock(srv, &flow, device).await;
    let code = cb
        .login_code
        .unwrap_or_else(|| panic!("login_code expected, got error {:?}", cb.error));
    exchange(srv, code.expose_secret(), &flow.verifier, device).await
}
