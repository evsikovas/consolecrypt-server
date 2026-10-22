// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! New-device protection (security audit 2026-10-21 S1, protocol 1.7):
//! new-device mail + event, "This wasn't me" links, quarantine, envelope
//! limits shared by replicas, and the password-reset revocations.

mod common;

use cc_protocol::devices::{DeviceInfo, ListDevicesResponse};
use cc_protocol::events::ServerEvent;
use cc_protocol::{paths, VaultId};
use common::*;
use consolecrypt_server::mail::MailKind;
use consolecrypt_server::Config;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn protect(c: &mut Config) {
    c.device_protection.enabled = true;
    // Mails link to `<public_url>/account#action=deny-device&token=…`.
    c.public_url = Some("https://account.example.test".into());
}

async fn devices(srv: &TestServer, s: &Session) -> ListDevicesResponse {
    let (status, body) = srv.get(paths::DEVICES, &s.access).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

fn find<'a>(list: &'a ListDevicesResponse, s: &Session) -> &'a DeviceInfo {
    list.devices
        .iter()
        .find(|d| d.device_id == s.device.id)
        .expect("device listed")
}

async fn revoke(srv: &TestServer, by: &Session, target: &Session) -> (StatusCode, Value) {
    srv.post(
        &device_path(paths::DEVICE_REVOKE, target.device.id),
        Some(&by.access),
        &json!({}),
    )
    .await
}

async fn deny(srv: &TestServer, token: &str) -> (StatusCode, Value) {
    srv.post(paths::DEVICES_DENY, None, &json!({ "token": token }))
        .await
}

async fn material(srv: &TestServer, s: &Session, vault: VaultId) -> (StatusCode, Value) {
    srv.get(
        &format!("{}?vault_id={vault}", paths::RECOVERY_VAULT_ENVELOPE),
        &s.access,
    )
    .await
}

async fn alive(srv: &TestServer, s: &Session) -> bool {
    srv.get(paths::AUTH_ME, &s.access).await.0 == StatusCode::OK
}

async fn audit_count(srv: &TestServer, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event_type = $1")
        .bind(event_type)
        .fetch_one(&srv.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn off_by_default_keeps_the_old_behaviour() {
    let srv = server!();
    let (_, meta) = srv.get(paths::META, "").await;
    assert_eq!(meta["protocol_version"], "1.9");
    assert_eq!(meta["capabilities"]["device_protection"], false);

    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    // Unlimited unlock material, no mail, no quarantine.
    for _ in 0..8 {
        assert_eq!(material(&srv, &b, vault.id).await.0, StatusCode::OK);
    }
    let list = devices(&srv, &a).await;
    assert!(find(&list, &a).trusted);
    assert!(!find(&list, &b).trusted);
    assert!(find(&list, &b).quarantine_until.is_none());
    assert_eq!(srv.mailer.count(MailKind::NewDevice), 0);
    assert_eq!(revoke(&srv, &b, &a).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn new_device_gets_mail_event_and_a_working_deny_link() {
    let srv = server!(protect);
    let (_, meta) = srv.get(paths::META, "").await;
    assert_eq!(meta["capabilities"]["device_protection"], true);
    let a = srv.new_account().await;
    srv.create_vault(&a).await;
    // Registration is not a "new device" sign-in.
    assert_eq!(srv.mailer.count(MailKind::NewDevice), 0);
    let mut ws = ws_connect(&srv, &a.access).await.unwrap();
    let _hello = ws_event(&mut ws).await;

    let b = srv.new_device_session(&a, "Stranger laptop").await;
    assert!(
        matches!(ws_event(&mut ws).await, ServerEvent::DeviceAdded { device_id } if device_id == b.device.id)
    );
    match ws_event(&mut ws).await {
        ServerEvent::DeviceRegistered {
            device_id, name, ..
        } => {
            assert_eq!(device_id, b.device.id);
            assert_eq!(name, "Stranger laptop");
        }
        other => panic!("expected device_registered, got {other:?}"),
    }
    srv.mailer.wait_for(MailKind::NewDevice, 1).await;
    let body = srv
        .mailer
        .messages
        .lock()
        .unwrap()
        .iter()
        .find(|(k, _, _)| *k == MailKind::NewDevice)
        .map(|(_, _, b)| b.clone())
        .unwrap();
    assert!(body.contains("Stranger laptop") && body.contains("cli") && body.contains("UTC"));
    let token = srv
        .mailer
        .deny_token_for(&a.email, MailKind::NewDevice)
        .expect("deny token in the mail");

    // Listed as unconfirmed and in quarantine.
    let list = devices(&srv, &a).await;
    let info = find(&list, &b);
    assert!(!info.trusted);
    assert!(info.quarantine_until.is_some());
    assert!(
        find(&list, &a).quarantine_until.is_none(),
        "registration device"
    );

    let (status, body) = deny(&srv, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked_device_names"], json!(["Stranger laptop"]));
    assert!(!alive(&srv, &b).await);
    assert!(alive(&srv, &a).await);
    srv.mailer.wait_for(MailKind::DeviceRevoked, 1).await;
    assert_eq!(audit_count(&srv, "device_denied").await, 1);

    // Single use; garbage is the same generic error.
    assert_eq!(deny(&srv, &token).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(deny(&srv, "ccd_nope").await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deny_link_never_revokes_a_trusted_device() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    srv.mailer.wait_for(MailKind::NewDevice, 1).await;
    let token = srv
        .mailer
        .deny_token_for(&a.email, MailKind::NewDevice)
        .unwrap();
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    let (status, body) = deny(&srv, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["details"]["reason"], "device_trusted");
    assert!(alive(&srv, &b).await);
}

#[tokio::test]
async fn quarantined_device_cannot_revoke_trusted_devices() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let c = srv.new_device_session(&a, "C").await;
    // Unlocking makes B trusted but keeps its quarantine (TR-8).
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    let list = devices(&srv, &b).await;
    assert!(find(&list, &b).trusted);
    assert!(find(&list, &b).quarantine_until.is_some());

    let (status, body) = revoke(&srv, &b, &a).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "device_in_quarantine");
    assert!(body["details"]["until"].is_string());
    assert!(alive(&srv, &a).await);

    // Untrusted devices and itself: allowed.
    assert_eq!(revoke(&srv, &b, &c).await.0, StatusCode::NO_CONTENT);
    assert_eq!(revoke(&srv, &b, &b).await.0, StatusCode::NO_CONTENT);

    // A device past quarantine may revoke anything.
    let d = srv.new_device_session(&a, "D").await;
    assert_eq!(srv.attest(&d, &vault).await.0, StatusCode::OK);
    sqlx::query("UPDATE devices SET created_at = now() - interval '15 days' WHERE id = $1")
        .bind(uuid::Uuid::from(d.device.id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(revoke(&srv, &d, &a).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn logout_all_from_quarantine_keeps_trusted_sessions() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let c = srv.new_device_session(&a, "C").await;
    let (status, body) = srv
        .post(
            paths::AUTH_LOGOUT,
            Some(&b.access),
            &json!({ "all_sessions": true }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["trusted_devices_kept"], 1);
    assert_eq!(body["sessions_revoked"], 2);
    assert!(body["quarantine_until"].is_string());
    assert!(alive(&srv, &a).await);
    assert!(!alive(&srv, &b).await);
    assert!(!alive(&srv, &c).await);
    let _ = vault;

    // From a trusted device past quarantine: everything, as before (204).
    let c2 = srv.new_device_session(&a, "C2").await;
    let (status, _) = srv
        .post(
            paths::AUTH_LOGOUT,
            Some(&a.access),
            &json!({ "all_sessions": true }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!alive(&srv, &c2).await);
}

#[tokio::test]
async fn password_change_from_quarantine_keeps_trusted_devices_and_mails_owner() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "Intruder").await;
    let c = srv.new_device_session(&a, "C").await;
    // A pending reset link must not survive a password change (TR-12).
    let (status, _) = srv
        .post(
            paths::AUTH_PASSWORD_FORGOT,
            None,
            &json!({ "email": a.email }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    srv.mailer.wait_for(MailKind::PasswordReset, 1).await;
    let reset = srv
        .mailer
        .token_for(&a.email, MailKind::PasswordReset)
        .unwrap();

    let new_password = random_password();
    let (status, body) = srv
        .post(
            paths::AUTH_PASSWORD_CHANGE,
            Some(&b.access),
            &json!({ "current_password": a.password, "new_password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(alive(&srv, &a).await, "trusted device stays signed in");
    assert!(alive(&srv, &b).await, "the caller's session stays");
    assert!(!alive(&srv, &c).await, "untrusted devices are signed out");
    srv.mailer.wait_for(MailKind::PasswordChanged, 1).await;
    let token = srv
        .mailer
        .deny_token_for(&a.email, MailKind::PasswordChanged)
        .expect("deny link in the password-changed mail");
    let (status, _) = srv
        .post(
            paths::AUTH_PASSWORD_RESET,
            None,
            &json!({ "token": reset, "new_password": random_password() }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reset token was invalidated"
    );
    assert_eq!(deny(&srv, &token).await.0, StatusCode::OK);
    assert!(!alive(&srv, &b).await);
}

#[tokio::test]
async fn approval_by_a_device_past_quarantine_lifts_it() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    let v = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let (status, body) = srv
        .post(
            paths::DEVICES,
            Some(&b.access),
            &json!({ "vault_ids": [v.id] }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let request_id = serde_json::from_value(body["request_id"].clone()).unwrap();
    let (status, body) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(&a.device, request_id, &b.device, &[v.id], now_unix()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list = devices(&srv, &b).await;
    assert!(find(&list, &b).trusted);
    assert!(find(&list, &b).quarantine_until.is_none());
    assert_eq!(audit_count(&srv, "device_quarantine_lifted").await, 1);
}

#[tokio::test]
async fn unlock_material_is_limited_per_account_and_mailed_once() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let mut untrusted = Vec::new();
    for i in 0..6 {
        untrusted.push(srv.new_device_session(&a, &format!("U{i}")).await);
    }
    for s in &untrusted[..5] {
        assert_eq!(material(&srv, s, vault.id).await.0, StatusCode::OK);
        // The same material again within the hour is not counted.
        assert_eq!(material(&srv, s, vault.id).await.0, StatusCode::OK);
    }
    let (status, body) = material(&srv, &untrusted[5], vault.id).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "envelope_rate_limited");
    assert!(body["retry_after_seconds"].as_u64().unwrap() >= 1);
    // The other endpoint shares the limit.
    let (status, _) = srv
        .get(
            &cc_protocol::paths::fill(
                paths::VAULT_ENVELOPES,
                &[("vault_id", &vault.id.to_string())],
            ),
            &untrusted[5].access,
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // The trusted device is never limited.
    for _ in 0..3 {
        assert_eq!(material(&srv, &a, vault.id).await.0, StatusCode::OK);
    }
    assert_eq!(audit_count(&srv, "envelope_issued_untrusted").await, 5);
    assert_eq!(audit_count(&srv, "envelope_rate_limited").await, 2);
    srv.mailer.wait_for(MailKind::EnvelopeAbuse, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(srv.mailer.count(MailKind::EnvelopeAbuse), 1, "once per day");
    assert!(srv
        .mailer
        .deny_token_for(&a.email, MailKind::EnvelopeAbuse)
        .is_some());

    // Unlocking (attest) still works for a device that got its material:
    // the main "new computer + vault passphrase" path.
    assert_eq!(srv.attest(&untrusted[0], &vault).await.0, StatusCode::OK);
    assert_eq!(
        material(&srv, &untrusted[0], vault.id).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn unlock_material_is_limited_per_device_and_per_day() {
    let srv = server!(|c: &mut Config| {
        protect(c);
        c.device_protection.envelopes_per_account_per_hour = 100;
        c.device_protection.envelopes_per_account_per_day = 4;
    });
    let a = srv.new_account().await;
    let vaults = [
        srv.create_vault(&a).await,
        srv.create_vault(&a).await,
        srv.create_vault(&a).await,
        srv.create_vault(&a).await,
    ];
    let b = srv.new_device_session(&a, "B").await;
    for v in &vaults[..3] {
        assert_eq!(material(&srv, &b, v.id).await.0, StatusCode::OK);
    }
    let (status, body) = material(&srv, &b, vaults[3].id).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "device hour: {body}");
    // Daily account limit: 3 used, one more device gets one, then refused.
    let c = srv.new_device_session(&a, "C").await;
    assert_eq!(material(&srv, &c, vaults[0].id).await.0, StatusCode::OK);
    let (status, body) = material(&srv, &c, vaults[1].id).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "account day: {body}");
}

#[tokio::test]
async fn unlock_limit_holds_across_two_replicas_under_concurrency() {
    let srv = server!(protect);
    let replica = srv.replica(protect).await;
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let mut sessions = Vec::new();
    for i in 0..10 {
        sessions.push(srv.new_device_session(&a, &format!("R{i}")).await);
    }
    replica.share_signers(&srv);
    let results = futures_util::future::join_all(sessions.iter().enumerate().map(|(i, s)| {
        let target = if i % 2 == 0 { &srv } else { &replica };
        material(target, s, vault.id)
    }))
    .await;
    let ok = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    let limited = results
        .iter()
        .filter(|(s, b)| {
            *s == StatusCode::TOO_MANY_REQUESTS && b["code"] == "envelope_rate_limited"
        })
        .count();
    assert_eq!((ok, limited), (5, 5), "{results:?}");
}

#[tokio::test]
async fn new_device_mails_are_throttled_into_a_summary() {
    let srv = server!(|c: &mut Config| {
        protect(c);
        c.device_protection.new_device_mails_per_hour = 2;
    });
    let a = srv.new_account().await;
    for i in 0..4 {
        srv.new_device_session(&a, &format!("N{i}")).await;
    }
    srv.mailer.wait_for(MailKind::NewDevice, 3).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let bodies: Vec<String> = srv
        .mailer
        .messages
        .lock()
        .unwrap()
        .iter()
        .filter(|(k, _, _)| *k == MailKind::NewDevice)
        .map(|(_, _, b)| b.clone())
        .collect();
    assert_eq!(bodies.len(), 3, "two mails + one summary, then silence");
    assert!(bodies[0].contains("token=ccd_") && bodies[1].contains("token=ccd_"));
    assert!(!bodies[2].contains("token="));
}

#[tokio::test]
async fn password_reset_revokes_never_trusted_devices_and_old_tokens() {
    let srv = server!(protect);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    let c = srv.new_device_session(&a, "Never trusted").await;
    // Registration sent an email-verification code; it must die too.
    let verify = srv
        .mailer
        .token_for(&a.email, MailKind::VerifyEmail)
        .expect("verification code");

    srv.post(
        paths::AUTH_PASSWORD_FORGOT,
        None,
        &json!({ "email": a.email }),
    )
    .await;
    srv.mailer.wait_for(MailKind::PasswordReset, 1).await;
    let reset = srv
        .mailer
        .token_for(&a.email, MailKind::PasswordReset)
        .unwrap();
    let new_password = random_password();
    let (status, body) = srv
        .post(
            paths::AUTH_PASSWORD_RESET,
            None,
            &json!({ "token": reset, "new_password": new_password }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(!alive(&srv, &a).await && !alive(&srv, &b).await && !alive(&srv, &c).await);
    let (status, _) = srv
        .post(paths::AUTH_EMAIL_VERIFY, None, &json!({ "token": verify }))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "verification code invalidated"
    );

    // Trusted devices sign in again; the never-trusted one is revoked.
    assert_eq!(
        srv.login(&a.email, &new_password, &a.device).await.0,
        StatusCode::OK
    );
    assert_eq!(
        srv.login(&a.email, &new_password, &b.device).await.0,
        StatusCode::OK
    );
    let (status, body) = srv.login(&a.email, &new_password, &c.device).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "device_revoked");

    // The reset mail lists it and its link revokes untrusted newcomers.
    srv.mailer
        .wait_for(MailKind::PasswordResetCompleted, 1)
        .await;
    let mail = srv
        .mailer
        .messages
        .lock()
        .unwrap()
        .iter()
        .find(|(k, _, _)| *k == MailKind::PasswordResetCompleted)
        .map(|(_, _, b)| b.clone())
        .unwrap();
    assert!(mail.contains("Never trusted"));
    let token = srv
        .mailer
        .deny_token_for(&a.email, MailKind::PasswordResetCompleted)
        .unwrap();
    let device = TestDevice::new("After reset");
    let (status, body) = srv.login(&a.email, &new_password, &device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let intruder = srv.session(a.email.clone(), new_password.clone(), device, body);
    let (status, body) = deny(&srv, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names = body["revoked_device_names"].as_array().unwrap();
    assert!(names.contains(&json!("After reset")));
    assert!(!alive(&srv, &intruder).await);
    assert_eq!(
        srv.login(&a.email, &new_password, &a.device).await.0,
        StatusCode::OK
    );
}
