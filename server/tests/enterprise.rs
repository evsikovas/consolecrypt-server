// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Enterprise sign-in (protocol 1.8) against an in-process mock OIDC IdP:
//! account creation, repeat sign-in, second device, linking, conflicts, the
//! ТР-7 negative cases, login-code/PKCE/redirect checks, re-check and
//! revocation (ТР-6), password endpoints refused (ТР-2), the LDAP lockout
//! guard counters, and switching back to standard mode (acceptance §7.3).
//! Needs only PostgreSQL (`CC_TEST_DATABASE_URL`).

mod common;

use common::enterprise::*;
use common::{random_password, TestDevice, TestServer};
use consolecrypt_server::enterprise::lockout::{self, Scope};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;

macro_rules! server_standard {
    () => {
        match TestServer::spawn(|_| {}).await {
            Some(s) => s,
            None => return,
        }
    };
}

macro_rules! oidc_server {
    ($idp:expr, $dir:expr) => {
        oidc_server!($idp, $dir, |_c: &mut consolecrypt_server::Config| {})
    };
    ($idp:expr, $dir:expr, $extra:expr) => {{
        let idp = &$idp;
        let dir = &$dir;
        let extra = $extra;
        match TestServer::spawn(|c| {
            idp.configure(dir, c);
            extra(c);
        })
        .await
        {
            Some(s) => s,
            None => return,
        }
    }};
}

fn acme_email() -> String {
    format!("u{}@acme.test", uuid::Uuid::now_v7().simple())
}

async fn identity_count(srv: &TestServer, user: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM account_identities WHERE account_id = $1::uuid")
        .bind(user)
        .fetch_one(&srv.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn first_sign_in_creates_the_account_then_repeat_and_second_device() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir);

    let (_, meta) = srv.get(cc_protocol::paths::META, "").await;
    assert_eq!(
        meta["capabilities"]["auth"],
        json!({"mode": "enterprise", "provider": "oidc", "display_name": "Acme SSO"})
    );
    assert_eq!(meta["protocol_version"], "1.8");
    assert_eq!(meta["registration_open"], false);

    let user = MockUser::new(&acme_email());
    let device = TestDevice::new("Laptop");
    let (status, body) = mock_login(&srv, &idp, &user, &device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["email_verified"], true);
    let user_id = body["user_id"].as_str().unwrap().to_owned();
    assert_eq!(identity_count(&srv, &user_id).await, 1);
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1::uuid")
            .bind(&user_id)
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert!(
        hash.is_none(),
        "enterprise accounts have no account password"
    );
    // The account's first device is the owner's: no quarantine.
    let lifted: bool =
        sqlx::query_scalar("SELECT quarantine_lifted_at IS NOT NULL FROM devices WHERE id = $1")
            .bind(uuid::Uuid::from(device.id))
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert!(lifted);
    let upstream: bool = sqlx::query_scalar(
        "SELECT upstream_refresh_token IS NOT NULL FROM account_identities WHERE account_id = $1::uuid",
    )
    .bind(&user_id)
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert!(
        upstream,
        "the IdP refresh token is kept (sealed) for re-checks"
    );

    // Repeat sign-in on the same device (proof required, protocol 1.4).
    let (status, again) = mock_login(&srv, &idp, &user, &device).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["user_id"], user_id.as_str());

    // Second device: same account, a new untrusted device (S1 rules).
    let second = TestDevice::new("Phone");
    let (status, other) = mock_login(&srv, &idp, &user, &second).await;
    assert_eq!(status, StatusCode::OK, "{other}");
    assert_eq!(other["user_id"], user_id.as_str());
    let lifted: bool =
        sqlx::query_scalar("SELECT quarantine_lifted_at IS NOT NULL FROM devices WHERE id = $1")
            .bind(uuid::Uuid::from(second.id))
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert!(!lifted, "a second device starts as a new, untrusted device");

    // The session works for normal API calls.
    let token = other["tokens"]["access_token"].as_str().unwrap();
    srv.register_signer(token, &second);
    let (status, me) = srv.get(cc_protocol::paths::AUTH_ME, token).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["email"], user.claims["email"]);

    // Email is only an attribute: a changed address follows the identity.
    let mut renamed = user.clone();
    let new_email = acme_email();
    renamed.claims.insert("email".into(), json!(new_email));
    let (status, body) = mock_login(&srv, &idp, &renamed, &device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], user_id.as_str());
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1::uuid")
        .bind(&user_id)
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(email, new_email);
}

#[tokio::test]
async fn password_endpoints_answer_enterprise_auth_required() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir);
    let device = TestDevice::new("Old app");
    let email = acme_email();
    let pw = random_password();
    let checks: Vec<(&str, Value)> = vec![
        (
            cc_protocol::paths::AUTH_REGISTER,
            json!({"email": email, "password": pw, "device": device.registration()}),
        ),
        (
            cc_protocol::paths::AUTH_LOGIN,
            json!({"email": email, "password": pw, "device": device.registration()}),
        ),
        (
            cc_protocol::paths::AUTH_PASSWORD_FORGOT,
            json!({"email": email}),
        ),
        (
            cc_protocol::paths::RECOVERY_ACCOUNT_START,
            json!({"email": email}),
        ),
        (
            cc_protocol::paths::AUTH_PASSWORD_RESET,
            json!({"token": "cct_x", "new_password": pw}),
        ),
        (
            cc_protocol::paths::RECOVERY_ACCOUNT_CONFIRM,
            json!({"token": "cct_x", "new_password": pw}),
        ),
        (
            cc_protocol::paths::AUTH_EMAIL_VERIFY,
            json!({"token": "cct_x"}),
        ),
    ];
    for (path, body) in checks {
        let (status, err) = srv.post(path, None, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {err}");
        assert_eq!(err["code"], "enterprise_auth_required", "{path}");
        assert!(
            err["message"].as_str().unwrap().contains("Update"),
            "{path}"
        );
    }
    // Password change from a signed-in enterprise session too.
    let user = MockUser::new(&acme_email());
    let (_, body) = mock_login(&srv, &idp, &user, &device).await;
    let token = body["tokens"]["access_token"].as_str().unwrap();
    srv.register_signer(token, &device);
    let (status, err) = srv
        .post(
            cc_protocol::paths::AUTH_PASSWORD_CHANGE,
            Some(token),
            &json!({"current_password": pw, "new_password": random_password()}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], "enterprise_auth_required");
    // LDAP endpoint is not enabled on an OIDC server.
    let (status, err) = srv
        .post(
            cc_protocol::paths::AUTH_LDAP_LOGIN,
            None,
            &json!({"login": "a", "password": "b", "device": device.registration()}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], "enterprise_auth_required");
}

#[tokio::test]
async fn standard_mode_is_unchanged_and_enterprise_routes_are_off() {
    let srv = server_standard!();
    let (_, meta) = srv.get(cc_protocol::paths::META, "").await;
    assert_eq!(meta["capabilities"]["auth"], json!({"mode": "standard"}));
    let a = srv.new_account().await;
    let (status, _) = srv.get(cc_protocol::paths::AUTH_ME, &a.access).await;
    assert_eq!(status, StatusCode::OK);
    let device = TestDevice::new("x");
    let (status, err) = exchange(&srv, "ccl_x", &"a".repeat(43), &device).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], "enterprise_auth_required");
    let r = no_redirect_client()
        .get(AppFlow::new().start_url(&srv, &device, None))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn id_token_negatives_create_nothing() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir);
    let device = TestDevice::new("x");
    for tweak in [
        Tweak::ForeignIssuer,
        Tweak::ForeignAudience,
        Tweak::BadNonce,
        Tweak::Expired,
        Tweak::AlgNone,
        Tweak::Hs256,
        Tweak::BadSignature,
        Tweak::UnknownKid,
    ] {
        let user = MockUser::new(&acme_email());
        idp.set_user(&user);
        idp.set_tweak(tweak);
        let flow = AppFlow::new();
        let cb = browser_via_mock(&srv, &flow, &device).await;
        assert!(cb.login_code.is_none(), "{tweak:?}");
        assert_eq!(
            cb.error.as_deref(),
            Some("invalid_credentials"),
            "{tweak:?}"
        );
    }
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM users").await, 0);
    let refused = srv
        .db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'login_failed'
               AND metadata->>'method' = 'oidc'",
        )
        .await;
    assert_eq!(refused, 8);
    // Unknown kid: exactly one rate-limited JWKS refetch (startup + 1).
    assert_eq!(idp.jwks_fetches(), 2);
    let user = MockUser::new(&acme_email());
    idp.set_user(&user);
    idp.set_tweak(Tweak::UnknownKid);
    let cb = browser_via_mock(&srv, &AppFlow::new(), &device).await;
    assert_eq!(cb.error.as_deref(), Some("invalid_credentials"));
    assert_eq!(idp.jwks_fetches(), 2, "refetch is rate limited");
}

#[tokio::test]
async fn state_swap_replay_and_foreign_redirect_uris_are_refused() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir);
    let device = TestDevice::new("x");
    let http = no_redirect_client();
    let user = MockUser::new(&acme_email());
    idp.set_user(&user);

    // Foreign redirect URIs never start a flow.
    for bad in [
        "https://evil.example/auth/callback",
        "http://localhost:5000/auth/callback",
        "http://127.0.0.1:5000/other",
        "http://127.0.0.1/auth/callback",
        "consolecrypt://evil/auth/callback",
        "http://127.0.0.1:5000@evil.example/auth/callback",
    ] {
        let mut flow = AppFlow::new();
        flow.redirect_uri = bad.into();
        let r = http
            .get(flow.start_url(&srv, &device, None))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad}");
        assert!(r.headers().get("location").is_none());
    }
    // Wrong challenge method / malformed challenge.
    let flow = AppFlow::new();
    let url = flow.start_url(&srv, &device, None).replace("S256", "plain");
    assert_eq!(
        http.get(url).send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM oidc_flows").await,
        0
    );
    // The mobile redirect URI is accepted.
    let mut mobile = AppFlow::new();
    mobile.redirect_uri = "consolecrypt://auth/callback".into();
    let cb = browser_via_mock(&srv, &mobile, &device).await;
    assert!(cb.login_code.is_some());

    // State swap: a forged or foreign state finds no flow.
    let flow = AppFlow::new();
    let r = http
        .get(flow.start_url(&srv, &device, None))
        .send()
        .await
        .unwrap();
    let r = http.get(location(&r)).send().await.unwrap();
    let callback = location(&r);
    let mut forged = reqwest::Url::parse(&callback).unwrap();
    let code = forged
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    forged
        .query_pairs_mut()
        .clear()
        .append_pair("code", &code)
        .append_pair("state", "attacker-state");
    let r = http.get(forged.as_str()).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.headers().get("location").is_none());
    // The genuine callback works once…
    let r = http.get(&callback).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FOUND);
    assert!(app_callback(&flow, &location(&r)).login_code.is_some());
    // …and is single use.
    let r = http.get(&callback).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // IdP-side refusal goes back to the app as an error.
    let flow = AppFlow::new();
    let r = http
        .get(flow.start_url(&srv, &device, None))
        .send()
        .await
        .unwrap();
    let authorize = reqwest::Url::parse(&location(&r)).unwrap();
    let state = authorize
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let mut cb_url = reqwest::Url::parse(&srv.url(cc_protocol::paths::AUTH_OIDC_CALLBACK)).unwrap();
    cb_url
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("error_description", "<script>alert(1)</script>")
        .append_pair("state", &state);
    let r = http.get(cb_url.as_str()).send().await.unwrap();
    let cb = app_callback(&flow, &location(&r));
    assert_eq!(cb.error.as_deref(), Some("forbidden"));
    assert!(!cb.error_description.unwrap().contains("script"));
}

#[tokio::test]
async fn login_code_is_single_use_and_bound_to_verifier_and_device() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir);
    let device = TestDevice::new("x");
    let user = MockUser::new(&acme_email());
    idp.set_user(&user);

    // Replay.
    let flow = AppFlow::new();
    let code = browser_via_mock(&srv, &flow, &device)
        .await
        .login_code
        .unwrap();
    let (status, _) = exchange(&srv, code.expose_secret(), &flow.verifier, &device).await;
    assert_eq!(status, StatusCode::OK);
    let (status, err) = exchange(&srv, code.expose_secret(), &flow.verifier, &device).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "invalid_credentials");

    // Wrong verifier burns the code.
    let flow = AppFlow::new();
    let code = browser_via_mock(&srv, &flow, &device)
        .await
        .login_code
        .unwrap();
    let (status, err) = exchange(
        &srv,
        code.expose_secret(),
        &b64(&common::random::<32>()),
        &device,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    let (status, _) = exchange(&srv, code.expose_secret(), &flow.verifier, &device).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the code was consumed");

    // Another device cannot redeem the code.
    let flow = AppFlow::new();
    let code = browser_via_mock(&srv, &flow, &device)
        .await
        .login_code
        .unwrap();
    let thief = TestDevice::new("thief");
    let (status, _) = exchange(&srv, code.expose_secret(), &flow.verifier, &thief).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Expired code.
    let flow = AppFlow::new();
    let code = browser_via_mock(&srv, &flow, &device)
        .await
        .login_code
        .unwrap();
    sqlx::query("UPDATE oidc_login_codes SET expires_at = now() - interval '1 second' WHERE used_at IS NULL")
        .execute(&srv.state.db)
        .await
        .unwrap();
    let (status, _) = exchange(&srv, code.expose_secret(), &flow.verifier, &device).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Expired flow (10 min) at the callback.
    let http = no_redirect_client();
    let flow = AppFlow::new();
    let r = http
        .get(flow.start_url(&srv, &device, None))
        .send()
        .await
        .unwrap();
    let r = http.get(location(&r)).send().await.unwrap();
    sqlx::query("UPDATE oidc_flows SET expires_at = now() - interval '1 second'")
        .execute(&srv.state.db)
        .await
        .unwrap();
    let r = http.get(location(&r)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_domain_group_mfa_and_conflicts() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir, |c: &mut consolecrypt_server::Config| {
        let o = c.auth.oidc.as_mut().unwrap();
        o.required_claim = Some(("groups".into(), "consolecrypt-users".into()));
        o.require_mfa = true;
    });
    let device = TestDevice::new("x");
    let try_login = |user: MockUser| {
        let srv = &srv;
        let idp = &idp;
        let device = &device;
        async move {
            idp.set_user(&user);
            browser_via_mock(srv, &AppFlow::new(), device).await
        }
    };
    let mut ok = MockUser::new(&acme_email());
    ok.claims.insert("amr".into(), json!(["pwd", "mfa"]));

    let mut foreign = ok.clone();
    foreign.claims.insert("email".into(), json!("x@other.test"));
    assert_eq!(
        try_login(foreign).await.error.as_deref(),
        Some("domain_not_allowed")
    );

    let mut no_group = ok.clone();
    no_group.claims.insert("groups".into(), json!(["other"]));
    assert_eq!(
        try_login(no_group).await.error.as_deref(),
        Some("group_required")
    );

    let mut no_mfa = ok.clone();
    no_mfa.claims.insert("amr".into(), json!(["pwd"]));
    assert_eq!(
        try_login(no_mfa).await.error.as_deref(),
        Some("mfa_required")
    );

    assert!(try_login(ok.clone()).await.login_code.is_some());

    // Same email, different identity: never taken over.
    let mut impostor = MockUser::new(ok.claims["email"].as_str().unwrap());
    impostor.claims.insert("amr".into(), json!(["mfa"]));
    let cb = try_login(impostor).await;
    assert_eq!(cb.error.as_deref(), Some("identity_conflict"));
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM users").await, 1);
}

#[tokio::test]
async fn existing_password_account_is_linked_on_first_sign_in() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    // Standard server first: a password account with a session.
    let std_srv = server_standard!();
    let email = acme_email();
    let pw = random_password();
    let laptop = TestDevice::new("Laptop");
    let (status, body) = std_srv.register(&email, &pw, &laptop).await;
    assert_eq!(status, StatusCode::CREATED);
    let old = std_srv.session(email.clone(), pw.clone(), laptop, body);

    // The same database switched to enterprise mode.
    let srv = std_srv.replica(|c| idp.configure(&dir, c)).await;
    srv.share_signers(&std_srv);
    // Old password sessions cannot be refreshed: sign in again via SSO.
    let (status, err) = srv
        .post(
            cc_protocol::paths::AUTH_REFRESH,
            None,
            &json!({"refresh_token": old.refresh}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["code"], "enterprise_auth_required");

    let user = MockUser::new(&email);
    let (status, body) = mock_login(&srv, &idp, &user, &old.device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["user_id"],
        old.user_id.to_string(),
        "linked, not a new account"
    );
    let hash: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(uuid::Uuid::from(old.user_id))
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert!(hash.is_none(), "the account password is removed");
    let (status, _) = srv.get(cc_protocol::paths::AUTH_ME, &old.access).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "password sessions were signed out"
    );

    // Back to standard + admin set-password lets the user in by password
    // again (acceptance §7.3); enterprise again → IdP only.
    let new_pw = random_password();
    consolecrypt_server::admin::set_password(
        &std_srv.state.db,
        &std_srv.state.config,
        &email,
        &cc_protocol::auth::SecretString::new(new_pw.clone()),
    )
    .await
    .unwrap();
    let phone = TestDevice::new("Phone");
    let (status, body) = std_srv.login(&email, &new_pw, &phone).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, err) = srv.login(&email, &new_pw, &phone).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], "enterprise_auth_required");
    let (status, _) = mock_login(&srv, &idp, &user, &old.device).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unverified_or_unlisted_domains_are_not_linked_automatically() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let std_srv = server_standard!();
    let a = std_srv.new_account().await; // example.test, not in the allow-list
    let srv = std_srv
        .replica(|c| {
            idp.configure(&dir, c);
            c.auth.allowed_domains.clear();
        })
        .await;
    let user = MockUser::new(&a.email);
    idp.set_user(&user);
    let cb = browser_via_mock(&srv, &AppFlow::new(), &TestDevice::new("x")).await;
    assert_eq!(cb.error.as_deref(), Some("identity_conflict"));

    // With the domain allowed but email_verified=false at the IdP.
    let srv2 = std_srv
        .replica(|c| {
            idp.configure(&dir, c);
            c.auth.allowed_domains = vec!["example.test".into()];
        })
        .await;
    let mut unverified = MockUser::new(&a.email);
    unverified
        .claims
        .insert("email_verified".into(), json!(false));
    idp.set_user(&unverified);
    let cb = browser_via_mock(&srv2, &AppFlow::new(), &TestDevice::new("y")).await;
    assert_eq!(cb.error.as_deref(), Some("identity_conflict"));

    // The administrator links it by hand.
    consolecrypt_server::admin::identity_link(
        &srv2.state.db,
        &srv2.state.config,
        &a.email,
        &unverified.sub,
        None,
    )
    .await
    .unwrap();
    let (status, body) = mock_login(&srv2, &idp, &unverified, &TestDevice::new("z")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], a.user_id.to_string());
    // Unlink: the next sign-in is a conflict again (verified flag false).
    consolecrypt_server::admin::identity_unlink(&srv2.state.db, &a.email, None)
        .await
        .unwrap();
    let n = consolecrypt_server::admin::session_revoke(&srv2.state.db, &a.email)
        .await
        .unwrap();
    assert!(n >= 1);
}

#[tokio::test]
async fn auto_create_off_refuses_unknown_identities() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir, |c: &mut consolecrypt_server::Config| {
        c.auth.auto_create = false;
    });
    idp.set_user(&MockUser::new(&acme_email()));
    let cb = browser_via_mock(&srv, &AppFlow::new(), &TestDevice::new("x")).await;
    assert_eq!(cb.error.as_deref(), Some("forbidden"));
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM users").await, 0);
}

async fn refresh(srv: &TestServer, token: &str) -> (StatusCode, Value) {
    srv.post(
        cc_protocol::paths::AUTH_REFRESH,
        None,
        &json!({ "refresh_token": token }),
    )
    .await
}

async fn age_checks(srv: &TestServer, minutes: i32) {
    sqlx::query("UPDATE account_identities SET checked_at = now() - make_interval(mins => $1)")
        .bind(minutes)
        .execute(&srv.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn disabled_in_idp_revokes_every_session_on_refresh_or_sweep() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir);
    let user = MockUser::new(&acme_email());
    let laptop = TestDevice::new("Laptop");
    let phone = TestDevice::new("Phone");
    let (_, a) = mock_login(&srv, &idp, &user, &laptop).await;
    let (_, b) = mock_login(&srv, &idp, &user, &phone).await;
    let a = srv.session("".into(), "".into(), laptop, a);
    let b = srv.session("".into(), "".into(), phone, b);

    // Fresh check: no IdP call on refresh.
    let (status, a2) = refresh(&srv, &a.refresh).await;
    assert_eq!(status, StatusCode::OK, "{a2}");
    assert_eq!(idp.state.lock().unwrap().refresh_grants, 0);

    // Due: the IdP still accepts → refresh works, IdP token rotated.
    age_checks(&srv, 16).await;
    let (status, a3) = refresh(&srv, a2["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{a3}");
    assert_eq!(idp.state.lock().unwrap().refresh_grants, 1);

    // Disabled at the IdP → refused at the next due re-check.
    idp.state.lock().unwrap().disabled.insert(user.sub.clone());
    age_checks(&srv, 16).await;
    let (status, err) = refresh(&srv, a3["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["code"], "account_disabled");
    // Every session of the account is gone; the other device learns why.
    let (status, err) = refresh(&srv, &b.refresh).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], "account_disabled");
    let (status, _) = srv.get(cc_protocol::paths::AUTH_ME, &b.access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let revoked = srv
        .db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'enterprise_access_revoked'",
        )
        .await;
    assert_eq!(revoked, 1);

    // The background sweep revokes without waiting for a refresh.
    let other = MockUser::new(&acme_email());
    let dev = TestDevice::new("Desk");
    let (_, c) = mock_login(&srv, &idp, &other, &dev).await;
    let c = srv.session("".into(), "".into(), dev, c);
    let checked = consolecrypt_server::enterprise::recheck::sweep_once(&srv.state)
        .await
        .unwrap();
    assert_eq!(checked, 0, "fresh identities are not re-checked");
    idp.state.lock().unwrap().disabled.insert(other.sub.clone());
    age_checks(&srv, 16).await;
    let checked = consolecrypt_server::enterprise::recheck::sweep_once(&srv.state)
        .await
        .unwrap();
    assert_eq!(checked, 1);
    let (status, _) = srv.get(cc_protocol::paths::AUTH_ME, &c.access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, err) = refresh(&srv, &c.refresh).await;
    assert_eq!(err["code"], "account_disabled");
}

#[tokio::test]
async fn lost_group_claim_on_refresh_revokes() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir, |c: &mut consolecrypt_server::Config| {
        c.auth.oidc.as_mut().unwrap().required_claim =
            Some(("groups".into(), "consolecrypt-users".into()));
    });
    let user = MockUser::new(&acme_email());
    let dev = TestDevice::new("x");
    let (_, s) = mock_login(&srv, &idp, &user, &dev).await;
    let s = srv.session("".into(), "".into(), dev, s);
    idp.state.lock().unwrap().drop_groups_on_refresh = true;
    age_checks(&srv, 16).await;
    let (status, err) = refresh(&srv, &s.refresh).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["code"], "account_disabled");
}

#[tokio::test]
async fn idp_outage_keeps_sessions_within_grace_only() {
    let idp = MockIdp::start().await;
    let dir = SecretDir::new();
    let srv = oidc_server!(idp, dir, |c: &mut consolecrypt_server::Config| {
        c.auth.recheck_grace = Duration::from_secs(3600);
    });
    let user = MockUser::new(&acme_email());
    let dev = TestDevice::new("x");
    let (_, s) = mock_login(&srv, &idp, &user, &dev).await;
    let s = srv.session("".into(), "".into(), dev, s);
    idp.state.lock().unwrap().unavailable = true;
    age_checks(&srv, 30).await;
    let (status, r) = refresh(&srv, &s.refresh).await;
    assert_eq!(status, StatusCode::OK, "within grace: {r}");
    let unavailable: bool =
        sqlx::query_scalar("SELECT check_unavailable_since IS NOT NULL FROM account_identities")
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert!(unavailable);
    // Past interval + grace: refused (503), but nothing is revoked.
    age_checks(&srv, 16 + 61).await;
    let (status, err) = refresh(&srv, r["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{err}");
    assert_eq!(err["code"], "idp_unavailable");
    // The IdP comes back: the same refresh token still works.
    idp.state.lock().unwrap().unavailable = false;
    let (status, _) = refresh(&srv, r["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn ldap_lockout_guard_counts_in_postgres() {
    let srv = server_standard!();
    let db = &srv.state.db;
    let window = Duration::from_secs(900);
    let k = lockout::key(Scope::Login, &lockout::normalize_login(" Alice@ACME.test "));
    assert_eq!(k, lockout::key(Scope::Login, "alice@acme.test"));
    for _ in 0..3 {
        lockout::reserve(db, Scope::Login, &k, 3, window)
            .await
            .unwrap();
    }
    let err = lockout::reserve(db, Scope::Login, &k, 3, window)
        .await
        .unwrap_err();
    assert_eq!(err.code(), cc_protocol::ErrorCode::RateLimited);
    let resp = axum::response::IntoResponse::into_response(err);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=900).contains(&retry), "{retry}");
    // Another login is independent; success clears.
    let other = lockout::key(Scope::Login, "bob@acme.test");
    lockout::reserve(db, Scope::Login, &other, 3, window)
        .await
        .unwrap();
    lockout::clear(db, Scope::Login, &k).await.unwrap();
    lockout::reserve(db, Scope::Login, &k, 3, window)
        .await
        .unwrap();
    // A passed window starts over.
    for _ in 0..3 {
        let _ = lockout::reserve(db, Scope::Login, &other, 3, window).await;
    }
    sqlx::query("UPDATE ldap_login_failures SET window_start = now() - interval '16 minutes'")
        .execute(db)
        .await
        .unwrap();
    lockout::reserve(db, Scope::Login, &other, 3, window)
        .await
        .unwrap();
    // IP scope counts failures only.
    let ip = lockout::ip_key("192.0.2.7".parse().unwrap());
    lockout::check(db, Scope::Ip, &ip, 2, window).await.unwrap();
    lockout::record_failure(db, Scope::Ip, &ip, window)
        .await
        .unwrap();
    lockout::check(db, Scope::Ip, &ip, 2, window).await.unwrap();
    lockout::record_failure(db, Scope::Ip, &ip, window)
        .await
        .unwrap();
    assert!(lockout::check(db, Scope::Ip, &ip, 2, window).await.is_err());
    assert!(
        lockout::check(db, Scope::Ip, &ip, 0, window).await.is_ok(),
        "0 = off"
    );
    // Shared by replicas: a second server sees the same counters.
    let replica = srv.replica(|_| {}).await;
    assert!(lockout::check(&replica.state.db, Scope::Ip, &ip, 2, window)
        .await
        .is_err());
    // Nothing identifying is stored in clear.
    let keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ldap_login_failures WHERE position('alice' in encode(key, 'escape')) > 0",
    )
    .fetch_one(db)
    .await
    .unwrap();
    assert_eq!(keys, 0);
}
