// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Quotas and request limits (security audit S2): unknown deletes,
//! tombstone/object accounting, device limits, PostgreSQL token buckets
//! shared by replicas, sign-in limits that others cannot use to lock the
//! owner out, observe mode and per-account overrides.

mod common;

use cc_protocol::sync::{MutationResult, PushResponse};
use cc_protocol::{paths, ObjectId};
use common::*;
use consolecrypt_server::config::{Config, Limit, LimitSpec, RateLimitMode};
use consolecrypt_server::mail::MailKind;
use reqwest::StatusCode;
use serde_json::{json, Value};

fn results(body: Value) -> PushResponse {
    serde_json::from_value(body).expect("PushResponse")
}

fn enforce(c: &mut Config) {
    c.rate_limits.enabled = true;
    c.rate_limits.mode = RateLimitMode::Enforce;
    c.rate_limits.auth_per_ip_per_minute = 10_000;
    c.rate_limits
        .limits
        .set(Limit::AuthIp, LimitSpec::per_minute(10_000));
    c.trust_proxy_headers = true;
}

/// Login as if from `ip` (the test server trusts `X-Forwarded-For`).
async fn login_from(
    srv: &TestServer,
    ip: &str,
    email: &str,
    password: &str,
    device: &TestDevice,
) -> (StatusCode, Value, Option<String>) {
    let resp = srv
        .http
        .post(srv.url(paths::AUTH_LOGIN))
        .header("x-forwarded-for", ip)
        .json(&json!({
            "email": email,
            "password": password,
            "device": device.registration(),
            "device_proof": device.proof(),
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let retry = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body, retry)
}

async fn forgot_from(srv: &TestServer, ip: &str, email: &str) -> StatusCode {
    srv.http
        .post(srv.url(paths::AUTH_PASSWORD_FORGOT))
        .header("x-forwarded-for", ip)
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap()
        .status()
}

// ---- TR-1 / TR-2 ------------------------------------------------------------

#[tokio::test]
async fn deletes_of_unknown_objects_create_nothing_and_replay() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let o = ObjectId::new();
    assert_eq!(
        srv.push(&a, vault.id, vec![put(o, 0)]).await.0,
        StatusCode::OK
    );
    let deletes: Vec<_> = (0..500).map(|_| delete(ObjectId::new(), 0)).collect();
    let (status, body) = srv.push(&a, vault.id, deletes.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let r = results(body);
    assert_eq!(r.latest_sequence, 1);
    assert!(r.results.iter().all(|x| matches!(
        x,
        MutationResult::Accepted {
            revision: 1,
            sequence: 1,
            replayed: false,
            ..
        }
    )));
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        1
    );
    assert_eq!(
        srv.db_scalar_i64("SELECT last_sequence FROM vault_sequences")
            .await,
        1
    );
    // The same push again is answered from the idempotency log.
    let (status, body) = srv.push(&a, vault.id, deletes).await;
    assert_eq!(status, StatusCode::OK);
    let r = results(body);
    assert!(r.results.iter().all(|x| matches!(
        x,
        MutationResult::Accepted {
            revision: 1,
            sequence: 1,
            replayed: true,
            ..
        }
    )));
    // Create offline → push → delete still works as before.
    let n = ObjectId::new();
    assert_eq!(
        srv.push(&a, vault.id, vec![put(n, 0)]).await.0,
        StatusCode::OK
    );
    let (status, body) = srv.push(&a, vault.id, vec![delete(n, 1)]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(
        results(body).results[0],
        MutationResult::Accepted {
            revision: 2,
            sequence: 3,
            ..
        }
    ));
    let (_, changes) = srv.changes(&a, vault.id, 0).await;
    let items = changes["changes"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[1]["deleted"], true);
}

#[tokio::test]
async fn unknown_deletes_are_tombstones_without_quotas_v2() {
    let srv = server!(|c: &mut Config| c.quotas.v2_enabled = false);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let (status, body) = srv
        .push(&a, vault.id, vec![delete(ObjectId::new(), 0)])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(results(body).latest_sequence, 1);
    assert_eq!(
        srv.db_scalar_i64("SELECT tombstone_count FROM vault_sequences")
            .await,
        1
    );
}

#[tokio::test]
async fn objects_and_tombstones_are_counted_against_quotas() {
    let srv = server!(|c: &mut Config| {
        c.quotas.max_vault_objects = 3;
        c.quotas.tombstone_cost_bytes = 1000;
        c.max_vault_bytes = 1024 * 1024;
    });
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let (o1, o2, o3) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    assert_eq!(
        srv.push(&a, vault.id, vec![put(o1, 0), put(o2, 0), put(o3, 0)])
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["details"]["reason"], "object_limit");
    assert_eq!(body["details"]["limit"], 3);
    assert!(body.get("retry_after_seconds").is_none_or(Value::is_null));
    // Deleting a live object is always accepted; its tombstone still counts.
    assert_eq!(
        srv.push(&a, vault.id, vec![delete(o1, 1)]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)])
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Updating a live object is fine (no new object).
    assert_eq!(
        srv.push(&a, vault.id, vec![put(o2, 1)]).await.0,
        StatusCode::OK
    );
    let (objects, tombstones): (i64, i64) =
        sqlx::query_as("SELECT object_count, tombstone_count FROM vault_sequences")
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert_eq!((objects, tombstones), (3, 1));
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_objects")
            .await,
        3
    );

    // Bytes: tombstones cost CC_TOMBSTONE_COST_BYTES each.
    let srv = server!(|c: &mut Config| {
        c.quotas.tombstone_cost_bytes = 5_000;
        c.max_vault_bytes = 1024 * 1024;
    });
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let big = |id| {
        let mut m = put(id, 0);
        m.op = cc_protocol::sync::MutationOp::Put {
            body: common::body(1000 * 1000),
        };
        m
    };
    let ids: Vec<ObjectId> = (0..30).map(|_| ObjectId::new()).collect();
    assert_eq!(
        srv.push(&a, vault.id, ids.iter().map(|i| put(*i, 0)).collect())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        srv.push(&a, vault.id, ids.iter().map(|i| delete(*i, 1)).collect())
            .await
            .0,
        StatusCode::OK
    );
    // 30 tombstones × 5000 B = 150 kB + 1 MB > 1 MiB.
    let (status, body) = srv.push(&a, vault.id, vec![big(ObjectId::new())]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["details"]["reason"], "vault_quota");
}

// ---- TR-3 --------------------------------------------------------------------

#[tokio::test]
async fn device_limit_and_revocation_frees_a_slot() {
    let srv = server!(|c: &mut Config| c.quotas.max_devices_per_account = 3);
    let a = srv.new_account().await;
    let b = srv.new_device_session(&a, "B").await;
    srv.new_device_session(&a, "C").await;
    let d = TestDevice::new("D");
    let (status, body) = srv.login(&a.email, &a.password, &d).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["details"]["reason"], "device_limit");
    assert_eq!(body["details"]["limit"], 3);
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM devices").await,
        3,
        "no device and no session for the refused sign-in"
    );
    // Known devices still sign in.
    assert_eq!(
        srv.login(&a.email, &a.password, &b.device).await.0,
        StatusCode::OK
    );
    let (status, _) = srv
        .request::<()>(
            reqwest::Method::POST,
            &device_path(paths::DEVICE_REVOKE, b.device.id),
            Some(&a.access),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(srv.login(&a.email, &a.password, &d).await.0, StatusCode::OK);
}

#[tokio::test]
async fn new_devices_per_day_and_account_overrides() {
    let srv = server!(|c: &mut Config| c.quotas.new_devices_per_account_per_day = 2);
    let a = srv.new_account().await;
    srv.new_device_session(&a, "B").await;
    let (status, body) = srv
        .login(&a.email, &a.password, &TestDevice::new("C"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["details"]["reason"], "device_daily_limit");
    assert!(body["details"]["until"].is_string());
    // An administrator raises the account's limit; it applies at once to a
    // replica that has not cached the account yet.
    consolecrypt_server::admin::limits_set(
        &srv.state.db,
        &a.email,
        &["new_devices_per_account_per_day=5".to_owned()],
    )
    .await
    .unwrap();
    let fresh = srv
        .replica(|c| c.quotas.new_devices_per_account_per_day = 2)
        .await;
    let (status, body) = fresh
        .login(&a.email, &a.password, &TestDevice::new("C"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(consolecrypt_server::admin::limits_set(
        &srv.state.db,
        &a.email,
        &["max_devices_per_account=65".to_owned()],
    )
    .await
    .is_err());
    let shown =
        consolecrypt_server::admin::limits_show(&srv.state.db, &srv.state.config, Some(&a.email))
            .await
            .unwrap();
    assert!(shown
        .iter()
        .any(|l| l.starts_with("new_devices_per_account_per_day") && l.ends_with("5*")));
    assert_eq!(
        consolecrypt_server::admin::limits_reset(&srv.state.db, &a.email, &[])
            .await
            .unwrap(),
        1
    );
}

// ---- TR-4 / TR-5 / TR-6 ----------------------------------------------------

#[tokio::test]
async fn push_limit_holds_across_two_replicas() {
    let cfg = |c: &mut Config| {
        enforce(c);
        c.rate_limits.limits.set(
            Limit::PushDevice,
            LimitSpec {
                rate: 1.0 / 60.0,
                burst: 6.0,
                per_hour: 0,
                per_day: 0,
            },
        );
    };
    let srv = server!(cfg);
    let replica = srv.replica(cfg).await;
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    replica.share_signers(&srv);
    let mut statuses = Vec::new();
    let mut last = Value::Null;
    let mut retry_header = None;
    for i in 0..8 {
        let target = if i % 2 == 0 { &srv } else { &replica };
        let body = json!({
            "vault_id": vault.id,
            "device_id": a.device.id,
            "mutations": [put(ObjectId::new(), 0)],
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let req = target
            .http
            .post(target.url(paths::SYNC_PUSH))
            .bearer_auth(&a.access)
            .header("content-type", "application/json")
            .body(bytes.clone());
        let resp = target
            .signed(req, &a.access, "POST", paths::SYNC_PUSH, &bytes)
            .send()
            .await
            .unwrap();
        statuses.push(resp.status());
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            retry_header = resp.headers().get("retry-after").cloned();
            last = resp.json().await.unwrap();
        }
    }
    assert_eq!(&statuses[..6], &[StatusCode::OK; 6], "{statuses:?}");
    assert_eq!(&statuses[6..], &[StatusCode::TOO_MANY_REQUESTS; 2]);
    assert_eq!(last["code"], "rate_limited");
    assert_eq!(last["details"]["limit"], "push_device");
    assert!(last["retry_after_seconds"].as_u64().unwrap() >= 50);
    assert!(retry_header.is_some());
}

#[tokio::test]
async fn mutations_are_counted_and_observe_mode_only_counts() {
    let cfg = |mode: RateLimitMode| {
        move |c: &mut Config| {
            enforce(c);
            c.rate_limits.mode = mode;
            c.rate_limits.limits.set(
                Limit::MutationsAccount,
                LimitSpec {
                    rate: 10.0 / 3600.0,
                    burst: 10.0,
                    per_hour: 0,
                    per_day: 0,
                },
            );
        }
    };
    let srv = server!(cfg(RateLimitMode::Enforce));
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let batch = |n| (0..n).map(|_| put(ObjectId::new(), 0)).collect::<Vec<_>>();
    assert_eq!(srv.push(&a, vault.id, batch(8)).await.0, StatusCode::OK);
    let (status, body) = srv.push(&a, vault.id, batch(3)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["details"]["limit"], "mutations_account");
    assert_eq!(srv.push(&a, vault.id, batch(2)).await.0, StatusCode::OK);

    let srv = server!(cfg(RateLimitMode::Observe));
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    for _ in 0..3 {
        assert_eq!(srv.push(&a, vault.id, batch(8)).await.0, StatusCode::OK);
    }
    // The refusal is audited once (observe mode included).
    for _ in 0..50 {
        if srv
            .db_scalar_i64("SELECT count(*) FROM audit_events WHERE event_type = 'limit_exceeded'")
            .await
            > 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM audit_events WHERE event_type = 'limit_exceeded'")
            .await,
        1
    );
}

#[tokio::test]
async fn account_override_changes_a_rate_limit() {
    let srv = server!(|c: &mut Config| {
        enforce(c);
        c.rate_limits.limits.set(
            Limit::UnknownDeleteAccount,
            LimitSpec {
                rate: 2.0 / 86_400.0,
                burst: 2.0,
                per_hour: 0,
                per_day: 0,
            },
        );
    });
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let deletes = |n| {
        (0..n)
            .map(|_| delete(ObjectId::new(), 0))
            .collect::<Vec<_>>()
    };
    assert_eq!(srv.push(&a, vault.id, deletes(2)).await.0, StatusCode::OK);
    let (status, body) = srv.push(&a, vault.id, deletes(1)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["details"]["limit"], "unknown_delete_account");
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM sync_mutations")
            .await,
        2,
        "a refused push commits nothing"
    );

    let b = server!(|c: &mut Config| {
        enforce(c);
        c.rate_limits.limits.set(
            Limit::UnknownDeleteAccount,
            LimitSpec {
                rate: 2.0 / 86_400.0,
                burst: 2.0,
                per_hour: 0,
                per_day: 0,
            },
        );
    });
    let acc = b.new_account().await;
    let vault = b.create_vault(&acc).await;
    consolecrypt_server::admin::limits_set(
        &b.state.db,
        &acc.email,
        &[
            "unknown_delete_account_rate=100/day".to_owned(),
            "unknown_delete_account_burst=100".to_owned(),
        ],
    )
    .await
    .unwrap();
    for _ in 0..3 {
        let (status, body) = b.push(&acc, vault.id, deletes(2)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn trust_requests_and_websockets_are_limited() {
    let srv = server!(|c: &mut Config| {
        enforce(c);
        c.rate_limits
            .limits
            .set(Limit::TrustRequestAccount, LimitSpec::per_minute(1));
        c.rate_limits
            .limits
            .set(Limit::WsConnectAccount, LimitSpec::per_minute(1));
    });
    let a = srv.new_account().await;
    srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let (status, body) = srv
        .post(paths::DEVICES, Some(&b.access), &json!({ "vault_ids": [] }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = srv
        .post(paths::DEVICES, Some(&b.access), &json!({ "vault_ids": [] }))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["details"]["limit"], "trust_request_account");

    assert!(ws_connect(&srv, &a.access).await.is_ok());
    assert_eq!(ws_connect(&srv, &a.access).await.err(), Some(429));
}

// ---- TR-7 / TR-8 -----------------------------------------------------------

#[tokio::test]
async fn failed_sign_ins_from_many_networks_do_not_lock_out_the_owner() {
    let cfg = |c: &mut Config| {
        enforce(c);
        c.rate_limits.limits.set(
            Limit::LoginEmail,
            LimitSpec {
                rate: 3.0 / 60.0,
                burst: 3.0,
                per_hour: 5,
                per_day: 0,
            },
        );
        c.rate_limits.limits.set(
            Limit::LoginEmailTotal,
            LimitSpec {
                rate: 20.0 / 3600.0,
                burst: 20.0,
                per_hour: 0,
                per_day: 0,
            },
        );
    };
    let srv = server!(cfg);
    let replica = srv.replica(cfg).await;
    let a = srv.new_account().await;
    // A successful sign-in costs nothing.
    for _ in 0..5 {
        assert_eq!(
            login_from(&srv, "203.0.113.5", &a.email, &a.password, &a.device)
                .await
                .0,
            StatusCode::OK
        );
    }
    // The attack: wrong passwords from 10 networks, through both replicas.
    let mut limited = 0;
    for i in 0..60 {
        let target = if i % 2 == 0 { &srv } else { &replica };
        let attacker = TestDevice::new("attacker");
        let ip = format!("198.51.{}.{}", 100 + i % 10, i);
        let (status, body, retry) =
            login_from(target, &ip, &a.email, "wrong-password-xyz", &attacker).await;
        match status {
            StatusCode::UNAUTHORIZED => {}
            StatusCode::TOO_MANY_REQUESTS => {
                limited += 1;
                assert!(retry.is_some());
                let limit = body["details"]["limit"].as_str().unwrap().to_owned();
                assert!(limit == "login_email" || limit == "login_email_total");
            }
            other => panic!("unexpected {other}: {body}"),
        }
    }
    // 10 networks × 3 per network would allow 30; the total stops at 20.
    assert_eq!(limited, 40);
    // Per (e-mail, network): the 4th failure in a minute from one /24.
    // The owner's known device signs in — from an attacked network too.
    let (status, body, _) =
        login_from(&replica, "198.51.100.77", &a.email, &a.password, &a.device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A new device of the owner waits for the total limit like anyone.
    let (status, body, _) = login_from(
        &srv,
        "192.0.2.10",
        &a.email,
        &a.password,
        &TestDevice::new("new laptop"),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["details"]["limit"], "login_email_total");
    // One mail and one audit event, however long the attack goes on.
    srv.mailer.wait_for(MailKind::FailedLogins, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(srv.mailer.count(MailKind::FailedLogins), 1);
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'limit_exceeded'
               AND metadata->>'limit' = 'login_email_total'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn new_device_of_the_owner_signs_in_while_other_networks_are_limited() {
    let srv = server!(|c: &mut Config| {
        enforce(c);
        c.rate_limits
            .limits
            .set(Limit::LoginEmail, LimitSpec::per_minute(3));
    });
    let a = srv.new_account().await;
    for i in 0..6 {
        let (status, _, _) = login_from(
            &srv,
            "198.51.100.9",
            &a.email,
            "wrong-password-xyz",
            &TestDevice::new(&format!("x{i}")),
        )
        .await;
        let expected = if i < 3 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(status, expected);
    }
    let (status, body, _) = login_from(
        &srv,
        "192.0.2.10",
        &a.email,
        &a.password,
        &TestDevice::new("new phone"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A proof whose nonce was already used is no "known device".
    let replay = a.device.proof();
    sqlx::query(
        "INSERT INTO device_login_nonces (device_id, nonce, expires_at)
         VALUES ($1, $2, now() + interval '1 hour')",
    )
    .bind(uuid::Uuid::from(a.device.id))
    .bind(
        serde_json::from_value::<cc_protocol::Bytes>(replay["nonce"].clone())
            .unwrap()
            .as_slice(),
    )
    .execute(&srv.state.db)
    .await
    .unwrap();
    let resp = srv
        .http
        .post(srv.url(paths::AUTH_LOGIN))
        .header("x-forwarded-for", "198.51.100.9")
        .json(&json!({
            "email": a.email,
            "password": a.password,
            "device": a.device.registration(),
            "device_proof": replay,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    // A fresh proof of the same device is.
    let (status, body, _) =
        login_from(&srv, "198.51.100.9", &a.email, &a.password, &a.device).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn recovery_requests_of_others_do_not_block_the_owner() {
    let srv = server!(|c: &mut Config| {
        enforce(c);
        c.rate_limits.limits.set(
            Limit::RecoveryEmail,
            LimitSpec {
                rate: 2.0 / 3600.0,
                burst: 2.0,
                per_hour: 0,
                per_day: 0,
            },
        );
        c.rate_limits.limits.set(
            Limit::RecoveryEmailTotal,
            LimitSpec {
                rate: 3.0 / 86_400.0,
                burst: 3.0,
                per_hour: 0,
                per_day: 0,
            },
        );
    });
    let a = srv.new_account().await;
    // The owner signed in from 192.0.2.0/24 before.
    assert_eq!(
        login_from(&srv, "192.0.2.10", &a.email, &a.password, &a.device)
            .await
            .0,
        StatusCode::OK
    );
    let unknown = random_email();
    // Others, from 5 networks: per-network limit only; same answers for an
    // existing and an unknown address.
    for i in 0..5 {
        let ip = format!("198.51.{}.1", 100 + i);
        for email in [&a.email, &unknown] {
            assert_eq!(forgot_from(&srv, &ip, email).await, StatusCode::ACCEPTED);
            assert_eq!(forgot_from(&srv, &ip, email).await, StatusCode::ACCEPTED);
            assert_eq!(
                forgot_from(&srv, &ip, email).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
    }
    // 10 requests for the owner's address, but only 3 mails went out.
    srv.mailer.wait_for(MailKind::PasswordReset, 3).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(srv.mailer.count(MailKind::PasswordReset), 3);
    // The owner, from the network they sign in from, still gets the mail.
    assert_eq!(
        forgot_from(&srv, "192.0.2.99", &a.email).await,
        StatusCode::ACCEPTED
    );
    srv.mailer.wait_for(MailKind::PasswordReset, 4).await;
}

#[tokio::test]
async fn rate_bucket_check_is_fast() {
    let srv = server!(enforce);
    let a = srv.new_account().await;
    let checks = [consolecrypt_server::limiter::Check::new(
        Limit::PushAccount,
        consolecrypt_server::limiter::Key::Account(a.user_id),
    )];
    let mut times = Vec::new();
    for _ in 0..200 {
        let t = std::time::Instant::now();
        srv.state
            .rate
            .take(&srv.state, Some(a.user_id), &checks)
            .await
            .unwrap()
            .ok();
        times.push(t.elapsed());
    }
    times.sort();
    let p95 = times[189];
    eprintln!("rate bucket check p95 = {p95:?}");
    assert!(p95 < std::time::Duration::from_millis(50), "p95 {p95:?}");
}
