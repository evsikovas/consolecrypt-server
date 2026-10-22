// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Enterprise OIDC sign-in against a real Keycloak (`tests/stands`,
//! container `cc-test-keycloak`). Env-gated: runs only with
//! `CC_TEST_KEYCLOAK=1` (see `tests/stands/README.md`), plus the usual
//! `CC_TEST_DATABASE_URL`.
//!
//! The browser leg is scripted: the server's start URL, Keycloak's login
//! form (cookies kept by hand — Keycloak marks them `Secure` even on
//! loopback HTTP), the server callback, the app redirect.

mod common;

use common::enterprise::*;
use common::{TestDevice, TestServer};
use consolecrypt_server::config::{
    AuthConfig, AuthModeKind, OidcConfig, OidcPreset, ProviderKind, TokenAuthMethod,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

struct Kc {
    issuer: String,
    client_id: String,
    client_secret: String,
    admin_url: String,
    realm: String,
    admin_user: String,
    admin_password: String,
    user_password: String,
    group: String,
}

fn kc() -> Option<Kc> {
    if std::env::var("CC_TEST_KEYCLOAK").ok().as_deref() != Some("1") {
        eprintln!("skipping Keycloak test: run tests/stands/stands.py up keycloak and set CC_TEST_KEYCLOAK=1");
        return None;
    }
    let v = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is required"));
    Some(Kc {
        issuer: v("CC_TEST_KEYCLOAK_ISSUER"),
        client_id: v("CC_TEST_KEYCLOAK_CLIENT_ID"),
        client_secret: v("CC_TEST_KEYCLOAK_CLIENT_SECRET"),
        admin_url: v("CC_TEST_KEYCLOAK_ADMIN_URL"),
        realm: std::env::var("CC_TEST_KEYCLOAK_REALM").unwrap_or_else(|_| "cc-test".into()),
        admin_user: v("CC_TEST_KEYCLOAK_ADMIN_USER"),
        admin_password: v("CC_TEST_KEYCLOAK_ADMIN_PASSWORD"),
        user_password: v("CC_TEST_KEYCLOAK_USER_PASSWORD"),
        group: v("CC_TEST_KEYCLOAK_GROUP"),
    })
}

impl Kc {
    fn configure(&self, dir: &SecretDir, c: &mut consolecrypt_server::Config) {
        let secret = dir.write("client-secret", self.client_secret.as_bytes());
        let key = dir.write("token-key", b64(&common::random::<32>()).as_bytes());
        c.auth = AuthConfig {
            mode: AuthModeKind::Enterprise,
            provider: Some(ProviderKind::Oidc),
            display_name: Some("Keycloak".into()),
            allowed_domains: vec!["acme.test".into()],
            oidc: Some(OidcConfig {
                preset: OidcPreset::Keycloak,
                issuer: self.issuer.clone(),
                client_id: self.client_id.clone(),
                client_secret_file: secret,
                scopes: ["openid", "email", "profile", "offline_access"]
                    .map(String::from)
                    .to_vec(),
                email_claim: "email".into(),
                required_claim: Some(("groups".into(), self.group.clone())),
                require_mfa: false,
                mfa_acr_values: vec![],
                token_key_file: key,
                token_auth_method: TokenAuthMethod::Basic,
                ca_file: None,
                extra_auth_params: vec![],
            }),
            ..AuthConfig::standard()
        };
    }

    async fn admin_token(&self) -> String {
        let r: Value = reqwest::Client::new()
            .post(format!(
                "{}/realms/master/protocol/openid-connect/token",
                self.admin_url
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", &self.admin_user),
                ("password", &self.admin_password),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        r["access_token"].as_str().expect("admin token").to_owned()
    }

    /// Create a fresh user (optionally in the required group); returns
    /// (keycloak id, username, email).
    async fn create_user(&self, in_group: bool) -> (String, String, String) {
        let name = format!("t{}", uuid::Uuid::now_v7().simple());
        let email = format!("{name}@acme.test");
        let mut body = json!({
            "username": name, "email": email, "emailVerified": true, "enabled": true,
            "firstName": "Test", "lastName": "User",
            "credentials": [{"type": "password", "value": self.user_password, "temporary": false}],
        });
        if in_group {
            body["groups"] = json!([self.group]);
        }
        let token = self.admin_token().await;
        let r = reqwest::Client::new()
            .post(format!(
                "{}/admin/realms/{}/users",
                self.admin_url, self.realm
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED, "create Keycloak user");
        let id = location(&r).rsplit('/').next().unwrap().to_owned();
        (id, name, email)
    }

    async fn set_enabled(&self, id: &str, enabled: bool) {
        let token = self.admin_token().await;
        let r = reqwest::Client::new()
            .put(format!(
                "{}/admin/realms/{}/users/{id}",
                self.admin_url, self.realm
            ))
            .bearer_auth(&token)
            .json(&json!({ "enabled": enabled }))
            .send()
            .await
            .unwrap();
        assert!(
            r.status().is_success(),
            "update Keycloak user: {}",
            r.status()
        );
    }

    async fn delete_user(&self, id: &str) {
        let token = self.admin_token().await;
        let _ = reqwest::Client::new()
            .delete(format!(
                "{}/admin/realms/{}/users/{id}",
                self.admin_url, self.realm
            ))
            .bearer_auth(&token)
            .send()
            .await;
    }
}

fn keep_cookies(jar: &mut BTreeMap<String, String>, resp: &reqwest::Response) {
    for v in resp.headers().get_all("set-cookie") {
        let pair = v.to_str().unwrap().split(';').next().unwrap_or_default();
        if let Some((k, val)) = pair.split_once('=') {
            jar.insert(k.trim().to_owned(), val.trim().to_owned());
        }
    }
}

fn cookie_header(jar: &BTreeMap<String, String>) -> String {
    jar.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn login_form_action(html: &str) -> String {
    let form = html
        .find("id=\"kc-form-login\"")
        .expect("Keycloak login form");
    let tag_start = html[..form].rfind("<form").unwrap();
    let tag = &html[tag_start..html[tag_start..].find('>').unwrap() + tag_start];
    let action = tag.split("action=\"").nth(1).unwrap();
    action[..action.find('"').unwrap()].replace("&amp;", "&")
}

/// Browser leg through Keycloak; returns the app callback.
async fn browser_via_keycloak(
    srv: &TestServer,
    flow: &AppFlow,
    device: &TestDevice,
    username: &str,
    password: &str,
) -> cc_protocol::enterprise_auth::OidcAppCallback {
    let http = no_redirect_client();
    let r = http
        .get(flow.start_url(srv, device, Some(username)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "start");
    let auth_url = location(&r);
    let mut jar = BTreeMap::new();
    let r = http.get(&auth_url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "Keycloak login page");
    keep_cookies(&mut jar, &r);
    let action = login_form_action(&r.text().await.unwrap());
    let r = http
        .post(&action)
        .header("cookie", cookie_header(&jar))
        .form(&[
            ("username", username),
            ("password", password),
            ("credentialId", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "Keycloak accepted the login");
    let callback = location(&r);
    assert!(
        callback.starts_with(&srv.base),
        "back to the server: {callback}"
    );
    let r = http.get(&callback).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND, "server callback");
    app_callback(flow, &location(&r))
}

async fn keycloak_login(
    srv: &TestServer,
    kc: &Kc,
    username: &str,
    device: &TestDevice,
) -> (StatusCode, Value) {
    let flow = AppFlow::new();
    let cb = browser_via_keycloak(srv, &flow, device, username, &kc.user_password).await;
    let code = cb.login_code.unwrap_or_else(|| {
        panic!(
            "login_code expected, got {:?} {:?}",
            cb.error, cb.error_description
        )
    });
    exchange(srv, code.expose_secret(), &flow.verifier, device).await
}

macro_rules! kc_server {
    ($kc:expr, $dir:expr, $extra:expr) => {{
        let kc = &$kc;
        let dir = &$dir;
        let extra = $extra;
        match TestServer::spawn(|c| {
            kc.configure(dir, c);
            extra(c);
        })
        .await
        {
            Some(s) => s,
            None => return,
        }
    }};
}

#[tokio::test]
async fn keycloak_account_creation_repeat_login_and_second_device() {
    let Some(kc) = kc() else { return };
    let dir = SecretDir::new();
    let srv = kc_server!(kc, dir, |_c: &mut consolecrypt_server::Config| {});
    let (kc_id, username, email) = kc.create_user(true).await;

    let laptop = TestDevice::new("Laptop");
    let (status, first) = keycloak_login(&srv, &kc, &username, &laptop).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let user_id = first["user_id"].as_str().unwrap().to_owned();
    let created: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1::uuid")
        .bind(&user_id)
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(created, email);
    let (issuer, has_rt): (String, bool) = sqlx::query_as(
        "SELECT issuer, upstream_refresh_token IS NOT NULL FROM account_identities
          WHERE account_id = $1::uuid",
    )
    .bind(&user_id)
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(issuer, kc.issuer);
    assert!(has_rt, "offline/refresh token stored for re-checks");

    let (status, again) = keycloak_login(&srv, &kc, &username, &laptop).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["user_id"], user_id.as_str());

    let phone = TestDevice::new("Phone");
    let (status, second) = keycloak_login(&srv, &kc, &username, &phone).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["user_id"], user_id.as_str());
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM devices").await,
        2,
        "second device registered"
    );

    // Real refresh-token re-check at Keycloak while the user is enabled.
    let s = srv.session(email.clone(), String::new(), phone, second);
    sqlx::query("UPDATE account_identities SET checked_at = now() - interval '1 hour'")
        .execute(&srv.state.db)
        .await
        .unwrap();
    let (status, r) = srv
        .post(
            cc_protocol::paths::AUTH_REFRESH,
            None,
            &json!({"refresh_token": s.refresh}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    kc.delete_user(&kc_id).await;
}

#[tokio::test]
async fn keycloak_user_outside_the_group_is_refused() {
    let Some(kc) = kc() else { return };
    let dir = SecretDir::new();
    let srv = kc_server!(kc, dir, |_c: &mut consolecrypt_server::Config| {});
    let (kc_id, username, _) = kc.create_user(false).await;
    let flow = AppFlow::new();
    let cb = browser_via_keycloak(
        &srv,
        &flow,
        &TestDevice::new("x"),
        &username,
        &kc.user_password,
    )
    .await;
    assert_eq!(cb.error.as_deref(), Some("group_required"));
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM users").await, 0);
    kc.delete_user(&kc_id).await;
}

/// Acceptance §7.5: a user disabled in the IdP loses every session no later
/// than RECHECK_MINUTES + 1 minute (real time, background sweep cadence).
#[tokio::test]
async fn keycloak_disabled_user_loses_sessions_within_recheck_interval() {
    let Some(kc) = kc() else { return };
    let dir = SecretDir::new();
    let srv = kc_server!(kc, dir, |c: &mut consolecrypt_server::Config| {
        c.auth.recheck_interval = Duration::from_secs(60);
    });
    let (kc_id, username, email) = kc.create_user(true).await;
    let laptop = TestDevice::new("Laptop");
    let phone = TestDevice::new("Phone");
    let (_, a) = keycloak_login(&srv, &kc, &username, &laptop).await;
    let (_, b) = keycloak_login(&srv, &kc, &username, &phone).await;
    let a = srv.session(email.clone(), String::new(), laptop, a);
    let b = srv.session(email.clone(), String::new(), phone, b);

    kc.set_enabled(&kc_id, false).await;
    let disabled_at = Instant::now();
    // The sweep runs every minute in production; poll it more often here.
    loop {
        consolecrypt_server::enterprise::recheck::sweep_once(&srv.state)
            .await
            .unwrap();
        let (status, _) = srv.get(cc_protocol::paths::AUTH_ME, &a.access).await;
        if status == StatusCode::UNAUTHORIZED {
            break;
        }
        assert!(
            disabled_at.elapsed() < Duration::from_secs(60 + 60),
            "sessions must be revoked within RECHECK_MINUTES + 1 minute"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    eprintln!(
        "revoked {:?} after disabling in Keycloak",
        disabled_at.elapsed()
    );
    for s in [&a, &b] {
        let (status, err) = srv
            .post(
                cc_protocol::paths::AUTH_REFRESH,
                None,
                &json!({"refresh_token": s.refresh}),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert_eq!(err["code"], "account_disabled");
    }
    // A disabled user cannot sign in again either (Keycloak refuses).
    kc.set_enabled(&kc_id, true).await;
    let (status, _) = keycloak_login(&srv, &kc, &username, &TestDevice::new("New")).await;
    assert_eq!(status, StatusCode::OK, "re-enabled user signs in again");
    kc.delete_user(&kc_id).await;
}

#[tokio::test]
async fn keycloak_refresh_recheck_revokes_disabled_user() {
    let Some(kc) = kc() else { return };
    let dir = SecretDir::new();
    let srv = kc_server!(kc, dir, |_c: &mut consolecrypt_server::Config| {});
    let (kc_id, username, email) = kc.create_user(true).await;
    let dev = TestDevice::new("Laptop");
    let (_, a) = keycloak_login(&srv, &kc, &username, &dev).await;
    let a = srv.session(email, String::new(), dev, a);
    kc.set_enabled(&kc_id, false).await;
    sqlx::query("UPDATE account_identities SET checked_at = now() - interval '16 minutes'")
        .execute(&srv.state.db)
        .await
        .unwrap();
    let (status, err) = srv
        .post(
            cc_protocol::paths::AUTH_REFRESH,
            None,
            &json!({"refresh_token": a.refresh}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["code"], "account_disabled");
    kc.delete_user(&kc_id).await;
}
