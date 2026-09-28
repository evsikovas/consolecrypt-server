// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Accounts, sessions, token rotation / replay, password flows.

mod common;

use cc_protocol::auth::{AccountInfo, TokenPair};
use cc_protocol::paths;
use common::*;
use consolecrypt_server::mail::MailKind;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn register_login_me_and_duplicates() {
    let srv = server!();
    let a = srv.new_account().await;

    let (status, body) = srv.get(paths::AUTH_ME, &a.access).await;
    assert_eq!(status, StatusCode::OK);
    let me: AccountInfo = serde_json::from_value(body).unwrap();
    assert_eq!(me.user_id, a.user_id);
    assert_eq!(me.email, a.email);
    assert_eq!(me.current_device_id, a.device.id);
    assert!(!me.email_verified);

    // Same email (different case) → 409.
    let (status, body) = srv
        .register(
            &a.email.to_uppercase(),
            &random_password(),
            &TestDevice::new("x"),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "already_exists");
    assert_eq!(body["details"]["field"], "email");

    // Login with the same device again reuses it.
    let (status, body) = srv.login(&a.email, &a.password, &a.device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_status"], "active");
}

#[tokio::test]
async fn wrong_password_and_unknown_email_look_the_same() {
    let srv = server!();
    let a = srv.new_account().await;
    let (s1, b1) = srv
        .login(&a.email, "definitely-wrong-password", &a.device)
        .await;
    let (s2, b2) = srv
        .login(
            &random_email(),
            "definitely-wrong-password",
            &TestDevice::new("x"),
        )
        .await;
    assert_eq!(s1, StatusCode::UNAUTHORIZED);
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(b1["code"], "invalid_credentials");
    assert_eq!(b1["code"], b2["code"]);
    assert_eq!(b1["message"], b2["message"]);
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM audit_events WHERE event_type = 'login_failed'")
            .await,
        1
    );
}

#[tokio::test]
async fn input_validation() {
    let srv = server!();
    let d = TestDevice::new("d");
    let (status, body) = srv.register("not-an-email", &random_password(), &d).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = srv.register(&random_email(), "short", &d).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Invalid (small-order) signing key.
    let mut reg = serde_json::to_value(d.registration()).unwrap();
    let mut identity = [0u8; 32];
    identity[0] = 1;
    reg["signing_public_key"] = json!(cc_protocol::Bytes::new(identity.to_vec()));
    let (status, _) = srv
        .post(
            paths::AUTH_REGISTER,
            None,
            &json!({"email": random_email(), "password": random_password(), "device": reg}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn device_id_conflicts() {
    let srv = server!();
    let a = srv.new_account().await;
    let b = srv.new_account().await;

    // A's device id presented for account B → 409.
    let (status, body) = srv.login(&b.email, &b.password, &a.device).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["details"]["field"], "device_id");

    // Same device id with different keys → 409.
    let mut impostor = TestDevice::new("impostor");
    impostor.id = a.device.id;
    let (status, body) = srv.login(&a.email, &a.password, &impostor).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["details"]["field"], "device_id");
}

#[tokio::test]
async fn refresh_rotates_and_detects_reuse() {
    let srv = server!();
    let a = srv.new_account().await;

    let (status, body) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({ "refresh_token": a.refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pair: TokenPair = serde_json::from_value(body).unwrap();
    assert_eq!(pair.session_id, a.session_id);
    let new_access = pair.access_token.expose_secret().to_owned();
    let new_refresh = pair.refresh_token.expose_secret().to_owned();
    assert_ne!(new_access, a.access);

    // The previous access token died with the rotation.
    let (status, _) = srv.get(paths::AUTH_ME, &a.access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = srv.get(paths::AUTH_ME, &new_access).await;
    assert_eq!(status, StatusCode::OK);

    // Replaying the used refresh token revokes the whole session.
    let (status, body) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({ "refresh_token": a.refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "refresh_token_reused");
    let (status, _) = srv.get(paths::AUTH_ME, &new_access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({ "refresh_token": new_refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'refresh_token_reuse'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn garbage_tokens_are_rejected() {
    let srv = server!();
    for token in [
        "",
        "cca_",
        "ccr_AAAA",
        "Bearer",
        "cca_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    ] {
        let (status, body) = srv.get(paths::AUTH_ME, token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token}");
        assert_eq!(body["code"], "unauthorized");
    }
    let (status, _) = srv
        .request::<()>(reqwest::Method::GET, paths::AUTH_ME, None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A refresh token is not an access token.
    let a = srv.new_account().await;
    let (status, _) = srv.get(paths::AUTH_ME, &a.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_and_logout_all() {
    let srv = server!();
    let a = srv.new_account().await;
    let b = srv.new_device_session(&a, "B").await;

    let (status, _) = srv
        .request::<()>(
            reqwest::Method::POST,
            paths::AUTH_LOGOUT,
            Some(&a.access),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        srv.get(paths::AUTH_ME, &a.access).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(srv.get(paths::AUTH_ME, &b.access).await.0, StatusCode::OK);
    // Refresh of a logged-out session fails.
    let (status, _) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({ "refresh_token": a.refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let c = srv.new_device_session(&a, "C").await;
    let (status, _) = srv
        .post(
            paths::AUTH_LOGOUT,
            Some(&c.access),
            &json!({ "all_sessions": true }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        srv.get(paths::AUTH_ME, &b.access).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        srv.get(paths::AUTH_ME, &c.access).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn password_reset_flow_keeps_vault_untouched() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let (status, _) = srv
        .push(&a, vault.id, vec![put(cc_protocol::ObjectId::new(), 0)])
        .await;
    assert_eq!(status, StatusCode::OK);
    let ciphertext_before: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM vault_objects")
        .fetch_one(&srv.state.db)
        .await
        .unwrap();

    // Unknown email → still 202, no mail.
    let (status, _) = srv
        .post(
            paths::AUTH_PASSWORD_FORGOT,
            None,
            &json!({ "email": random_email() }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let (status, _) = srv
        .post(
            paths::AUTH_PASSWORD_FORGOT,
            None,
            &json!({ "email": a.email }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let token = wait_for_token(&srv, &a.email, MailKind::PasswordReset).await;

    let new_password = random_password();
    let (status, body) = srv
        .post(
            paths::AUTH_PASSWORD_RESET,
            None,
            &json!({ "token": token, "new_password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // Single use.
    let (status, _) = srv
        .post(
            paths::AUTH_PASSWORD_RESET,
            None,
            &json!({ "token": token, "new_password": random_password() }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // All sessions revoked; old password rejected; new works.
    assert_eq!(
        srv.get(paths::AUTH_ME, &a.access).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        srv.login(&a.email, &a.password, &a.device).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = srv.login(&a.email, &new_password, &a.device).await;
    assert_eq!(status, StatusCode::OK);
    // Reset proved mailbox control → email verified.
    assert_eq!(body["email_verified"], true);

    // Vault ciphertext and device trust untouched: the old device still syncs.
    let relogged = srv.session(a.email.clone(), new_password, a.device, body);
    let (status, _) = srv.changes(&relogged, vault.id, 0).await;
    assert_eq!(status, StatusCode::OK);
    let ciphertext_after: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM vault_objects")
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(ciphertext_before, ciphertext_after);
}

#[tokio::test]
async fn account_recovery_does_not_grant_vault_access() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;

    let (status, _) = srv
        .post(
            paths::RECOVERY_ACCOUNT_START,
            None,
            &json!({ "email": a.email }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let token = wait_for_token(&srv, &a.email, MailKind::AccountRecovery).await;
    let new_password = random_password();
    let (status, _) = srv
        .post(
            paths::RECOVERY_ACCOUNT_CONFIRM,
            None,
            &json!({ "token": token, "new_password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A brand-new device of the recovered account is NOT trusted.
    let fresh = TestDevice::new("new laptop");
    let (status, body) = srv.login(&a.email, &new_password, &fresh).await;
    assert_eq!(status, StatusCode::OK);
    let s = srv.session(a.email.clone(), new_password, fresh, body);
    let (status, body) = srv.changes(&s, vault.id, 0).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "device_not_trusted");
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type IN
               ('account_recovery_started', 'account_recovery_completed')"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn change_password_revokes_other_sessions() {
    let srv = server!();
    let a = srv.new_account().await;
    let b = srv.new_device_session(&a, "B").await;
    let new_password = random_password();

    let (status, body) = srv
        .post(
            paths::AUTH_PASSWORD_CHANGE,
            Some(&a.access),
            &json!({ "current_password": "wrong-password-123", "new_password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_credentials");

    let (status, _) = srv
        .post(
            paths::AUTH_PASSWORD_CHANGE,
            Some(&a.access),
            &json!({ "current_password": a.password, "new_password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(srv.get(paths::AUTH_ME, &a.access).await.0, StatusCode::OK);
    assert_eq!(
        srv.get(paths::AUTH_ME, &b.access).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        srv.login(&a.email, &new_password, &a.device).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn email_verification() {
    let srv = server!(|c| c.require_email_verification = true);
    let a = srv.new_account().await;

    // Unverified: no vault creation, no login from another device.
    let vault = TestVault::new();
    let (status, body) = srv
        .post(
            paths::VAULTS,
            Some(&a.access),
            &vault.create_request(a.device.id),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "email_not_verified");
    let (status, body) = srv
        .login(&a.email, &a.password, &TestDevice::new("B"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "email_not_verified");

    let token = wait_for_token(&srv, &a.email, MailKind::VerifyEmail).await;
    let (status, _) = srv
        .post(paths::AUTH_EMAIL_VERIFY, None, &json!({ "token": token }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = srv.login(&a.email, &a.password, &a.device).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email_verified"], true);
    let s = srv.session(a.email.clone(), a.password.clone(), a.device, body);
    let (status, _) = srv
        .post(
            paths::VAULTS,
            Some(&s.access),
            &vault.create_request(s.device.id),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn registration_can_be_closed() {
    let srv = server!(|c| c.registration_open = false);
    let (status, body) = srv
        .register(&random_email(), &random_password(), &TestDevice::new("x"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");
    let (_, meta) = srv
        .request::<()>(reqwest::Method::GET, paths::META, None, None)
        .await;
    assert_eq!(meta["registration_open"], false);
}

#[tokio::test]
async fn auth_endpoints_are_rate_limited() {
    let srv = server!(|c| {
        c.rate_limits.enabled = true;
        c.rate_limits.login_per_email_per_minute = 3;
        c.rate_limits.auth_per_ip_per_minute = 1000;
    });
    let a = srv.new_account().await;
    let mut last = (StatusCode::OK, serde_json::Value::Null);
    for _ in 0..4 {
        last = srv.login(&a.email, "wrong-password-xyz", &a.device).await;
    }
    assert_eq!(last.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(last.1["code"], "rate_limited");
    assert!(last.1["retry_after_seconds"].as_u64().unwrap() >= 1);
}

async fn wait_for_token(srv: &TestServer, email: &str, kind: MailKind) -> String {
    for _ in 0..100 {
        if let Some(t) = srv.mailer.token_for(email, kind) {
            return t;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no {kind:?} mail for {email}");
}

#[tokio::test]
async fn recovery_mail_is_rate_limited_per_email() {
    let srv = server!(|c| {
        c.rate_limits.enabled = true;
        c.rate_limits.recovery_per_email_per_hour = 2;
        c.rate_limits.auth_per_ip_per_minute = 1000;
    });
    let a = srv.new_account().await;
    let mut statuses = Vec::new();
    for i in 0..4 {
        // Case variations hit the same bucket.
        let email = if i % 2 == 0 {
            a.email.clone()
        } else {
            a.email.to_uppercase()
        };
        let (s, _) = srv
            .post(
                paths::AUTH_PASSWORD_FORGOT,
                None,
                &json!({ "email": email }),
            )
            .await;
        statuses.push(s);
    }
    assert_eq!(
        statuses,
        vec![
            StatusCode::ACCEPTED,
            StatusCode::ACCEPTED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
    // Mail is sent in the background: wait for it (the machine may be busy).
    for _ in 0..250 {
        if srv.mailer.count(MailKind::PasswordReset) >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(srv.mailer.count(MailKind::PasswordReset), 2);
    // Another address is unaffected.
    let (s, _) = srv
        .post(
            paths::RECOVERY_ACCOUNT_START,
            None,
            &json!({ "email": random_email() }),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn auth_endpoints_are_rate_limited_per_ip() {
    let srv = server!(|c| {
        c.rate_limits.enabled = true;
        c.rate_limits.auth_per_ip_per_minute = 5;
    });
    let mut last = StatusCode::OK;
    let mut retry_after = None;
    for _ in 0..6 {
        let resp = srv
            .http
            .post(srv.url(paths::AUTH_REFRESH))
            .json(&json!({ "refresh_token": "ccr_x" }))
            .send()
            .await
            .unwrap();
        last = resp.status();
        retry_after = resp.headers().get("retry-after").cloned();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after.is_some());
    // Authenticated, non-auth endpoints are not throttled by this limiter.
    let (s, _) = srv.get(paths::META, "unused").await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn vault_access_key_guessing_is_rate_limited() {
    let srv = server!(|c| {
        c.rate_limits.enabled = true;
        c.rate_limits.proof_per_device_per_minute = 3;
    });
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let guess = TestVault {
            id: vault.id,
            vak: random::<32>(),
        };
        statuses.push(srv.attest(&b, &guess).await.0);
    }
    assert_eq!(&statuses[..3], &[StatusCode::UNPROCESSABLE_ENTITY; 3]);
    assert_eq!(statuses[4], StatusCode::TOO_MANY_REQUESTS);
    // Even the right key is refused while limited.
    assert_eq!(
        srv.attest(&b, &vault).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}
