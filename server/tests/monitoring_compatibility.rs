//! Actual HTTP + real owned TestDb transactions. No production endpoint,
//! policy witness fabrication or Rust-only bypass of the auth middleware.
mod common;
use cc_protocol::{paths, ObjectId, VaultId};
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
const VERSION: &str = "2.0.0"; // explicitly synthetic; NOT a declared shipped floor.
fn policy_path(vault: VaultId) -> String {
    format!("/v1/vaults/{vault}/compatibility/monitoring-settings")
}
async fn send(
    srv: &TestServer,
    session: &Session,
    method: Method,
    path: &str,
    version: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let bytes = body
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .unwrap()
        .unwrap_or_default();
    raw(
        srv,
        session,
        method,
        path,
        version,
        body.as_ref().map(|_| bytes.as_slice()),
    )
    .await
}
async fn raw(
    srv: &TestServer,
    session: &Session,
    method: Method,
    path: &str,
    version: Option<&str>,
    bytes: Option<&[u8]>,
) -> (StatusCode, Value) {
    let mut request = srv
        .http
        .request(method.clone(), srv.url(path))
        .bearer_auth(&session.access);
    if let Some(version) = version {
        request = request.header(cc_protocol::version::HEADER_CLIENT_VERSION, version);
    }
    let body = bytes.unwrap_or_default();
    request = srv.signed(request, &session.access, method.as_str(), path, body);
    if bytes.is_some() {
        request = request
            .header("content-type", "application/json")
            .body(body.to_vec());
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}
async fn account(srv: &TestServer, version: Option<&str>) -> Session {
    let email = random_email();
    let password = random_password();
    let device = TestDevice::new("Own compatibility device");
    let mut reg = serde_json::to_value(device.registration()).unwrap();
    if let Some(version) = version {
        reg["client_version"] = json!(version);
    } else {
        reg.as_object_mut().unwrap().remove("client_version");
    }
    let (status, body) = srv
        .post(
            paths::AUTH_REGISTER,
            None,
            &json!({"email":email,"password":password,"device":reg,"device_proof":device.proof()}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    srv.session(email, password, device, body)
}
async fn probe(srv: &TestServer, a: &Session, vault: VaultId) -> Value {
    let (status, body) = send(
        srv,
        a,
        Method::GET,
        &policy_path(vault),
        Some(VERSION),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "personalAccount");
    body
}
fn request(vault: &TestVault, view: &Value) -> Value {
    json!({"version":1,"expectedRevision":view["revision"],
  "expectedRosterDigest":view["rosterDigest"],"vaultAccessKey":vault.vak_bytes()})
}
async fn enable(srv: &TestServer, a: &Session, vault: &TestVault) -> Value {
    let view = probe(srv, a, vault.id).await;
    let (status, body) = send(
        srv,
        a,
        Method::PUT,
        &policy_path(vault.id),
        Some(VERSION),
        Some(request(vault, &view)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "enabled");
    body
}
async fn push(
    srv: &TestServer,
    a: &Session,
    vault: VaultId,
    version: Option<&str>,
) -> (StatusCode, Value) {
    send(
        srv,
        a,
        Method::POST,
        paths::SYNC_PUSH,
        version,
        Some(json!({"vault_id":vault,"device_id":a.device.id,
      "mutations":[put(ObjectId::new(),0)]})),
    )
    .await
}
async fn wait_lock(srv: &TestServer, label: &str) {
    tokio::time::timeout(Duration::from_secs(8),async {
      loop {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
           AND wait_event_type='Lock' AND position($1 in query)>0")
          .bind(label).fetch_one(&srv.state.db).await.unwrap();
        if count>0 {return;}tokio::time::sleep(Duration::from_millis(10)).await;
      }
    }).await.expect("actual database transaction barrier was not observed");
}
async fn count(srv: &TestServer, vault: VaultId) -> i64 {
    sqlx::query_scalar("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1")
        .bind(Uuid::from(vault))
        .fetch_one(&srv.state.db)
        .await
        .unwrap()
}
#[tokio::test]
async fn default_off_and_explicit_owner_strict_bounded_opt_in() {
    let off = server!();
    let a = account(&off, None).await;
    let vault = off.create_vault(&a).await;
    assert_eq!(push(&off, &a, vault.id, None).await.0, StatusCode::OK);
    let view = probe(&off, &a, vault.id).await;
    assert_eq!(view["state"], "off");
    assert!(view["offerMinimumClientVersion"].is_null());
    assert_eq!(
        send(
            &off,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(request(&vault, &view))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    let view = probe(&srv, &a, vault.id).await;
    for extra in ["isOwner", "approved", "minimumClientVersion", "sourceUrl"] {
        let mut body = request(&vault, &view);
        body[extra] = json!(true);
        assert_eq!(
            send(
                &srv,
                &a,
                Method::PUT,
                &policy_path(vault.id),
                Some(VERSION),
                Some(body)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let mut body = request(&vault, &view);
    body["version"] = json!(2);
    assert_eq!(
        send(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(body)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let duplicate=format!("{{\"version\":1,\"version\":1,\"expectedRevision\":0,\"expectedRosterDigest\":\"{}\",\"vaultAccessKey\":\"{}\"}}",
      view["rosterDigest"].as_str().unwrap(),vault.vak_bytes().to_base64());
    assert_eq!(
        raw(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(duplicate.as_bytes())
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        raw(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(&vec![b'x'; 4097])
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let other = account(&srv, Some(VERSION)).await;
    assert_eq!(
        send(
            &srv,
            &other,
            Method::GET,
            &policy_path(vault.id),
            Some(VERSION),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let mut wrong = request(&vault, &view);
    wrong["vaultAccessKey"] = json!(cc_protocol::Bytes::new(vec![0; 32]));
    assert_eq!(
        send(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(wrong)
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(probe(&srv, &a, vault.id).await["state"], "off");
}
#[tokio::test]
async fn unknown_old_prerelease_active_devices_block_but_revoked_are_excluded_and_cas_is_exact() {
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "Owned old second device").await;
    for version in [None, Some("1.0.0"), Some("3.0.0-beta.1"), Some("nonsense")] {
        sqlx::query("UPDATE devices SET client_version=$2,last_seen_at='2000-01-01' WHERE id=$1")
            .bind(Uuid::from(b.device.id))
            .bind(version)
            .execute(&srv.state.db)
            .await
            .unwrap();
        let view = probe(&srv, &a, vault.id).await;
        assert_eq!(
            send(
                &srv,
                &a,
                Method::PUT,
                &policy_path(vault.id),
                Some(VERSION),
                Some(request(&vault, &view))
            )
            .await
            .0,
            StatusCode::UPGRADE_REQUIRED
        );
    }
    let stale = probe(&srv, &a, vault.id).await;
    assert_eq!(
        srv.post(
            &format!("/v1/devices/{}/revoke", b.device.id),
            Some(&a.access),
            &json!({})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(request(&vault, &stale))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let enabled = enable(&srv, &a, &vault).await;
    assert_eq!(enabled["revision"], 1);
    assert_eq!(enabled["checkpoint"]["vaultSequence"], 0);
    assert_eq!(
        send(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(request(&vault, &stale))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    // Removing the operator offer is not an opt-out; the stored highest floor remains.
    let replica = srv
        .replica(|c| c.monitoring_preservation_minimum = None)
        .await;
    let path = paths::SYNC_PUSH;
    let body = serde_json::to_vec(
        &json!({"vault_id":vault.id,"device_id":a.device.id,"mutations":[put(ObjectId::new(),0)]}),
    )
    .unwrap();
    let request = replica
        .http
        .post(replica.url(path))
        .bearer_auth(&a.access)
        .header("content-type", "application/json")
        .header(cc_protocol::version::HEADER_CLIENT_VERSION, "1.0.0")
        .body(body.clone());
    let response = srv
        .signed(request, &a.access, "POST", path, &body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(count(&srv, vault.id).await, 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opt_in_blocks_old_request_already_past_middleware_on_second_vault_without_locking_other_account(
) {
    let srv = Arc::new(server!(
        |c| c.monitoring_preservation_minimum = Some(VERSION.into())
    ));
    let a = Arc::new(account(&srv, Some(VERSION)).await);
    let first = srv.create_vault(&a).await;
    let second = srv.create_vault(&a).await;
    let other = account(&srv, None).await;
    let unrelated = srv.create_vault(&other).await;
    // Warm the ordinary device observation cache; the old request below really
    // passes the nonlocking middleware policy check before opt-in commits.
    assert_eq!(
        send(&srv, &a, Method::GET, paths::DEVICES, Some(VERSION), None)
            .await
            .0,
        StatusCode::OK
    );
    let view = probe(&srv, &a, first.id).await;
    let body = request(&first, &view);
    let first_id = first.id;
    let second_id = second.id;
    let mut held = srv.state.db.begin().await.unwrap();
    sqlx::query("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1 FOR UPDATE")
        .bind(Uuid::from(first_id))
        .execute(&mut *held)
        .await
        .unwrap();
    let gate = tokio::spawn({
        let srv = srv.clone();
        let a = a.clone();
        async move {
            send(
                &srv,
                &a,
                Method::PUT,
                &policy_path(first_id),
                Some(VERSION),
                Some(body),
            )
            .await
        }
    });
    wait_lock(&srv, "cc.compat.checkpoint").await;
    let old = tokio::spawn({
        let srv = srv.clone();
        let a = a.clone();
        async move { push(&srv, &a, second_id, Some("1.0.0")).await }
    });
    wait_lock(&srv, "cc.compat.account").await;
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(3),
            push(&srv, &other, unrelated.id, None)
        )
        .await
        .unwrap()
        .0,
        StatusCode::OK
    );
    held.commit().await.unwrap();
    let (status, receipt) = gate.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["checkpoint"]["vaultSequence"], 0);
    assert_eq!(old.await.unwrap().0, StatusCode::UPGRADE_REQUIRED);
    assert_eq!(count(&srv, first_id).await, 0);
    assert_eq!(count(&srv, second_id).await, 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_before_opt_in_commits_first_and_each_vault_checkpoint_requires_its_own_pull() {
    let srv = Arc::new(server!(
        |c| c.monitoring_preservation_minimum = Some(VERSION.into())
    ));
    let a = Arc::new(account(&srv, Some(VERSION)).await);
    let first = srv.create_vault(&a).await;
    let second = srv.create_vault(&a).await;
    assert_eq!(
        send(&srv, &a, Method::GET, paths::DEVICES, Some(VERSION), None)
            .await
            .0,
        StatusCode::OK
    );
    let view = probe(&srv, &a, first.id).await;
    let body = request(&first, &view);
    let first_id = first.id;
    let second_id = second.id;
    let mut held = srv.state.db.begin().await.unwrap();
    sqlx::query("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1 FOR UPDATE")
        .bind(Uuid::from(second_id))
        .execute(&mut *held)
        .await
        .unwrap();
    let old = tokio::spawn({
        let srv = srv.clone();
        let a = a.clone();
        async move { push(&srv, &a, second_id, Some("1.0.0")).await }
    });
    wait_lock(&srv, "cc.sync.sequence").await;
    let gate = tokio::spawn({
        let srv = srv.clone();
        let a = a.clone();
        async move {
            send(
                &srv,
                &a,
                Method::PUT,
                &policy_path(first_id),
                Some(VERSION),
                Some(body),
            )
            .await
        }
    });
    wait_lock(&srv, "cc.compat.account").await;
    held.commit().await.unwrap();
    assert_eq!(old.await.unwrap().0, StatusCode::OK);
    assert_eq!(gate.await.unwrap().0, StatusCode::OK);
    let view = probe(&srv, &a, second_id).await;
    assert_eq!(view["checkpoint"]["vaultSequence"], 1);
    let epoch: Uuid = sqlx::query_scalar("SELECT epoch FROM vaults WHERE id=$1")
        .bind(Uuid::from(second_id))
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(view["checkpoint"]["vaultEpoch"], json!(epoch));
    assert_eq!(
        push(&srv, &a, second_id, Some("1.0.0")).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(count(&srv, second_id).await, 1);
    let path = format!("{}?vault_id={second_id}&after=0", paths::SYNC_CHANGES);
    assert_eq!(
        send(&srv, &a, Method::GET, &path, None, None).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    let (status, page) = send(&srv, &a, Method::GET, &path, Some(VERSION), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["latest_sequence"], view["checkpoint"]["vaultSequence"]);
    assert_eq!(page["epoch"], view["checkpoint"]["vaultEpoch"]);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_old_device_login_waits_for_opt_in_then_is_refused_before_device_or_session_insert() {
    let srv = Arc::new(server!(
        |c| c.monitoring_preservation_minimum = Some(VERSION.into())
    ));
    let a = Arc::new(account(&srv, Some(VERSION)).await);
    let vault = srv.create_vault(&a).await;
    let view = probe(&srv, &a, vault.id).await;
    let mut held = srv.state.db.begin().await.unwrap();
    sqlx::query("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1 FOR UPDATE")
        .bind(Uuid::from(vault.id))
        .execute(&mut *held)
        .await
        .unwrap();
    let body = request(&vault, &view);
    let vault_id = vault.id;
    let gate = tokio::spawn({
        let srv = srv.clone();
        let a = a.clone();
        async move {
            send(
                &srv,
                &a,
                Method::PUT,
                &policy_path(vault_id),
                Some(VERSION),
                Some(body),
            )
            .await
        }
    });
    wait_lock(&srv, "cc.compat.checkpoint").await;
    let device = TestDevice::new("Owned old login");
    let device_id = device.id;
    let mut reg = device.registration();
    reg.client_version = Some("1.0.0".into());
    let login =
        json!({"email":a.email,"password":a.password,"device":reg,"device_proof":device.proof()});
    let old = tokio::spawn({
        let srv = srv.clone();
        async move { srv.post(paths::AUTH_LOGIN, None, &login).await }
    });
    wait_lock(&srv, "cc.compat.account").await;
    held.commit().await.unwrap();
    assert_eq!(gate.await.unwrap().0, StatusCode::OK);
    assert_eq!(old.await.unwrap().0, StatusCode::UPGRADE_REQUIRED);
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1)")
        .bind(Uuid::from(device_id))
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
    assert!(!exists);
}
#[tokio::test]
async fn current_request_not_stored_version_controls_refresh_read_write_and_attestation() {
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    enable(&srv, &a, &vault).await;
    assert_eq!(
        push(&srv, &a, vault.id, None).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        push(&srv, &a, vault.id, Some("1.0.0")).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    // Even the fixed metadata route must not let an old/unknown current
    // request downgrade the stored roster report in an opted account.
    for version in [None, Some("1.0.0")] {
        assert_eq!(
            send(&srv, &a, Method::GET, &policy_path(vault.id), version, None)
                .await
                .0,
            StatusCode::UPGRADE_REQUIRED,
        );
    }
    let report: Option<String> =
        sqlx::query_scalar("SELECT client_version FROM devices WHERE id=$1")
            .bind(Uuid::from(a.device.id))
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    assert_eq!(report.as_deref(), Some(VERSION));
    let refresh = json!({"refresh_token":a.refresh});
    let bytes = serde_json::to_vec(&refresh).unwrap();
    let old = srv
        .signed(
            srv.http
                .post(srv.url(paths::AUTH_REFRESH))
                .header("content-type", "application/json")
                .header(cc_protocol::version::HEADER_CLIENT_VERSION, "1.0.0")
                .body(bytes.clone()),
            &a.access,
            "POST",
            paths::AUTH_REFRESH,
            &bytes,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UPGRADE_REQUIRED);
    let fresh = srv
        .signed(
            srv.http
                .post(srv.url(paths::AUTH_REFRESH))
                .header("content-type", "application/json")
                .header(cc_protocol::version::HEADER_CLIENT_VERSION, VERSION)
                .body(bytes.clone()),
            &a.access,
            "POST",
            paths::AUTH_REFRESH,
            &bytes,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), StatusCode::OK);
    // The old attempt did not consume the one-use refresh token. Use a separate
    // newly authenticated compatible device for the actual K(V) attest path.
    let device = TestDevice::new("Owned compatible attest");
    let mut reg = device.registration();
    reg.client_version = Some(VERSION.into());
    let (status,body)=srv.post(paths::AUTH_LOGIN,None,&json!({"email":a.email,"password":a.password,"device":reg,"device_proof":device.proof()})).await;
    assert_eq!(status, StatusCode::OK);
    let b = srv.session(a.email.clone(), a.password.clone(), device, body);
    let path = format!("/v1/devices/{}/attest", b.device.id);
    let body = json!({"vault_id":vault.id,"vault_access_key":vault.vak_bytes(),"envelope":device_envelope(b.device.id)});
    assert_eq!(
        send(
            &srv,
            &b,
            Method::POST,
            &path,
            Some("1.0.0"),
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(&srv, &b, Method::POST, &path, Some(VERSION), Some(body))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        push(&srv, &b, vault.id, Some(VERSION)).await.0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn restored_explicit_accounts_quarantine_preserves_highest_and_unrelated_legacy_rotation_is_unchanged(
) {
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    let enabled = enable(&srv, &a, &vault).await;
    let other = account(&srv, None).await;
    let unrelated = srv.create_vault(&other).await;
    let report = consolecrypt_server::compatibility::restore::quarantine_restored_accounts(
        &srv.state.db,
        &[a.user_id],
        "1.0.0",
    )
    .await
    .unwrap();
    assert_eq!(report.accounts, 1);
    assert_eq!(report.vaults, 1);
    let quarantined = probe(&srv, &a, vault.id).await;
    assert_eq!(quarantined["state"], "quarantined");
    assert_eq!(quarantined["minimumClientVersion"], VERSION);
    assert_ne!(
        quarantined["checkpoint"]["vaultEpoch"],
        enabled["checkpoint"]["vaultEpoch"]
    );
    assert_eq!(
        push(&srv, &a, vault.id, Some(VERSION)).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        push(&srv, &other, unrelated.id, None).await.0,
        StatusCode::OK
    );
    let (status, cleared) = send(
        &srv,
        &a,
        Method::PUT,
        &policy_path(vault.id),
        Some(VERSION),
        Some(request(&vault, &quarantined)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cleared["minimumClientVersion"], VERSION);
    assert_eq!(cleared["state"], "enabled");
    consolecrypt_server::admin::rotate_epoch(&srv.state.db, Some(unrelated.id))
        .await
        .unwrap();
    assert_eq!(
        push(&srv, &other, unrelated.id, None).await.0,
        StatusCode::OK
    );
    // A pre-policy backup has NO row: only explicit outside/manual floor input
    // can establish quarantine. Never infer the forgotten highest from the DB.
    consolecrypt_server::compatibility::restore::quarantine_restored_accounts(
        &srv.state.db,
        &[other.user_id],
        VERSION,
    )
    .await
    .unwrap();
    assert_eq!(
        push(&srv, &other, unrelated.id, None).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert!(
        consolecrypt_server::compatibility::restore::quarantine_restored_accounts(
            &srv.state.db,
            &[a.user_id],
            ""
        )
        .await
        .is_err()
    );
    assert_eq!(probe(&srv, &a, vault.id).await["state"], "enabled");
}

#[tokio::test]
async fn sticky_floor_cannot_decrease_and_a_legacy_proof_optional_replica_does_not_bypass_opted_scope(
) {
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    enable(&srv, &a, &vault).await;
    let lower = srv
        .replica(|c| c.monitoring_preservation_minimum = Some("1.0.0".into()))
        .await;
    lower.register_signer(&a.access, &a.device);
    let view = probe(&lower, &a, vault.id).await;
    let (status, after) = send(
        &lower,
        &a,
        Method::PUT,
        &policy_path(vault.id),
        Some(VERSION),
        Some(request(&vault, &view)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after["minimumClientVersion"], VERSION);
    let weak = srv
        .replica(|c| {
            c.monitoring_preservation_minimum = None;
            c.require_request_proof = false;
        })
        .await;
    let data =
        json!({"vault_id":vault.id,"device_id":a.device.id,"mutations":[put(ObjectId::new(),0)]});
    let response = weak
        .http
        .post(weak.url(paths::SYNC_PUSH))
        .bearer_auth(&a.access)
        .header(cc_protocol::version::HEADER_CLIENT_VERSION, VERSION)
        .json(&data)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(count(&srv, vault.id).await, 0);
    let other = account(&srv, None).await;
    let unrelated = srv.create_vault(&other).await;
    let data = json!({"vault_id":unrelated.id,"device_id":other.device.id,"mutations":[put(ObjectId::new(),0)]});
    let response = weak
        .http
        .post(weak.url(paths::SYNC_PUSH))
        .bearer_auth(&other.access)
        .json(&data)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn future_policy_schema_is_denied_without_reinterpretation_or_rewriting_by_owner_or_restore()
{
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    let before = enable(&srv, &a, &vault).await;
    // Isolated TestDb schema only: simulate a future migration/rolling deploy.
    sqlx::query("ALTER TABLE account_monitoring_compatibility DROP CONSTRAINT account_monitoring_compatibility_version_check")
      .execute(&srv.state.db).await.unwrap();
    sqlx::query("UPDATE account_monitoring_compatibility SET version=2 WHERE user_id=$1")
        .bind(Uuid::from(a.user_id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert_eq!(
        push(&srv, &a, vault.id, Some(VERSION)).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(
            &srv,
            &a,
            Method::GET,
            &policy_path(vault.id),
            Some(VERSION),
            None
        )
        .await
        .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(
            &srv,
            &a,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(request(&vault, &before))
        )
        .await
        .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert!(
        consolecrypt_server::compatibility::restore::quarantine_restored_accounts(
            &srv.state.db,
            &[a.user_id],
            VERSION
        )
        .await
        .is_err()
    );
    let row: (i32, i64) = sqlx::query_as(
        "SELECT version,revision FROM account_monitoring_compatibility WHERE user_id=$1",
    )
    .bind(Uuid::from(a.user_id))
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(row, (2, 1));
}

#[tokio::test]
async fn new_owner_device_bootstraps_only_personal_keys_and_self_attest_without_clearing_quarantine(
) {
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    let own_team = srv.create_vault(&a).await;
    // Isolated DB kind fixture for scope denial, not a fake team enrollment or
    // signed log witness. Even a malformed legacy team carrying key envelopes
    // must not enter this PERSONAL bootstrap allowlist.
    sqlx::query("UPDATE vaults SET kind='team' WHERE id=$1")
        .bind(Uuid::from(own_team.id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    let other = account(&srv, None).await;
    let foreign = srv.create_vault(&other).await;
    let foreign_team = srv.create_vault(&other).await;
    sqlx::query("UPDATE vaults SET kind='team' WHERE id=$1")
        .bind(Uuid::from(foreign_team.id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    consolecrypt_server::compatibility::restore::quarantine_restored_accounts(
        &srv.state.db,
        &[a.user_id],
        VERSION,
    )
    .await
    .unwrap();
    let device = TestDevice::new("Owned recovering new device");
    let mut reg = device.registration();
    reg.client_version = Some(VERSION.into());
    let (status,body)=srv.post(paths::AUTH_LOGIN,None,&json!({"email":a.email,"password":a.password,"device":reg,"device_proof":device.proof()})).await;
    assert_eq!(status, StatusCode::OK);
    let b = srv.session(a.email.clone(), a.password.clone(), device, body);
    assert_eq!(
        send(&srv, &b, Method::GET, paths::AUTH_ME, Some(VERSION), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&srv, &b, Method::GET, paths::DEVICES, Some(VERSION), None)
            .await
            .0,
        StatusCode::OK
    );
    let (status, list) = send(&srv, &b, Method::GET, paths::VAULTS, Some(VERSION), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["vault_id"] != json!(own_team.id)));
    let material = format!("{}?vault_id={}", paths::RECOVERY_VAULT_ENVELOPE, vault.id);
    let (status, keys) = send(&srv, &b, Method::GET, &material, Some(VERSION), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(keys["password_envelope"].is_object());
    assert_eq!(
        push(&srv, &b, vault.id, Some(VERSION)).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    let own_path = format!("/v1/devices/{}/attest", b.device.id);
    let payload = |id: VaultId, key: cc_protocol::Bytes| json!({"vault_id":id,"vault_access_key":key,"envelope":device_envelope(b.device.id)});
    assert_eq!(
        send(
            &srv,
            &b,
            Method::POST,
            &own_path,
            Some(VERSION),
            Some(payload(vault.id, cc_protocol::Bytes::new(vec![0; 32])))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for target in [&foreign, &foreign_team, &own_team] {
        let metadata = format!("/v1/vaults/{}", target.id);
        assert_eq!(
            send(&srv, &b, Method::GET, &metadata, Some(VERSION), None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let path = format!("{}?vault_id={}", paths::RECOVERY_VAULT_ENVELOPE, target.id);
        assert_eq!(
            send(&srv, &b, Method::GET, &path, Some(VERSION), None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(
                &srv,
                &b,
                Method::POST,
                &own_path,
                Some(VERSION),
                Some(payload(target.id, target.vak_bytes()))
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    let other_device_path = format!("/v1/devices/{}/attest", a.device.id);
    assert_eq!(
        send(
            &srv,
            &b,
            Method::POST,
            &other_device_path,
            Some(VERSION),
            Some(payload(vault.id, vault.vak_bytes()))
        )
        .await
        .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(&srv, &b, Method::GET, &material, Some("1.0.0"), None)
            .await
            .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(
            &srv,
            &b,
            Method::POST,
            &own_path,
            Some(VERSION),
            Some(payload(vault.id, vault.vak_bytes()))
        )
        .await
        .0,
        StatusCode::OK
    );
    let view = probe(&srv, &b, vault.id).await;
    assert_eq!(view["state"], "quarantined");
    assert_eq!(
        push(&srv, &b, vault.id, Some(VERSION)).await.0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(
            &srv,
            &b,
            Method::POST,
            paths::DEVICES,
            Some(VERSION),
            Some(json!({"vault_ids":[vault.id]}))
        )
        .await
        .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(
        send(
            &srv,
            &b,
            Method::POST,
            &format!("/v1/vaults/{}/envelopes", vault.id),
            Some(VERSION),
            Some(json!({}))
        )
        .await
        .0,
        StatusCode::UPGRADE_REQUIRED
    );
    let (status, receipt) = send(
        &srv,
        &b,
        Method::PUT,
        &policy_path(vault.id),
        Some(VERSION),
        Some(request(&vault, &view)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["state"], "enabled");
    assert_eq!(receipt["checkpoint"]["vaultSequence"], 0);
    assert_eq!(
        push(&srv, &b, vault.id, Some(VERSION)).await.0,
        StatusCode::OK
    );
    // Another account's own team metadata remains available without this floor.
    assert_eq!(
        send(
            &srv,
            &other,
            Method::GET,
            &format!("/v1/vaults/{}", foreign_team.id),
            None,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_and_opt_in_share_account_first_order_in_both_actual_database_interleavings() {
    for gate_first in [true, false] {
        let srv = Arc::new(server!(
            |c| c.monitoring_preservation_minimum = Some(VERSION.into())
        ));
        let a = Arc::new(account(&srv, Some(VERSION)).await);
        let vault = srv.create_vault(&a).await;
        let device = TestDevice::new("Owned revoke target");
        let mut reg = device.registration();
        reg.client_version = Some(VERSION.into());
        let (status,body)=srv.post(paths::AUTH_LOGIN,None,&json!({"email":a.email,"password":a.password,"device":reg,"device_proof":device.proof()})).await;
        assert_eq!(status, StatusCode::OK);
        let b = srv.session(a.email.clone(), a.password.clone(), device, body);
        let view = probe(&srv, &a, vault.id).await;
        let gate_body = request(&vault, &view);
        let vault_id = vault.id;
        let target = b.device.id;
        let revoke_path = format!("/v1/devices/{target}/revoke");
        let mut held = srv.state.db.begin().await.unwrap();
        if gate_first {
            sqlx::query("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1 FOR UPDATE")
                .bind(Uuid::from(vault_id))
                .execute(&mut *held)
                .await
                .unwrap();
        } else {
            sqlx::query("SELECT id FROM devices WHERE id=$1 FOR UPDATE")
                .bind(Uuid::from(target))
                .execute(&mut *held)
                .await
                .unwrap();
        }
        let launch_gate = || {
            let srv = srv.clone();
            let a = a.clone();
            let body = gate_body.clone();
            tokio::spawn(async move {
                send(
                    &srv,
                    &a,
                    Method::PUT,
                    &policy_path(vault_id),
                    Some(VERSION),
                    Some(body),
                )
                .await
            })
        };
        let launch_revoke = || {
            let srv = srv.clone();
            let a = a.clone();
            let path = revoke_path.clone();
            tokio::spawn(
                async move { send(&srv, &a, Method::POST, &path, None, Some(json!({}))).await },
            )
        };
        let (gate, revoke) = if gate_first {
            let gate = launch_gate();
            wait_lock(&srv, "cc.compat.checkpoint").await;
            let revoke = launch_revoke();
            wait_lock(&srv, "cc.compat.account").await;
            (gate, revoke)
        } else {
            let revoke = launch_revoke();
            wait_lock(&srv, "SELECT name, revoked_at IS NOT NULL FROM devices").await;
            let gate = launch_gate();
            wait_lock(&srv, "cc.compat.account").await;
            (gate, revoke)
        };
        held.commit().await.unwrap();
        let (gate, revoke) = tokio::time::timeout(Duration::from_secs(8), async {
            (gate.await.unwrap(), revoke.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(revoke.0, StatusCode::NO_CONTENT);
        assert_eq!(
            gate.0,
            if gate_first {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            }
        );
        assert_eq!(
            probe(&srv, &a, vault_id).await["state"],
            if gate_first { "enabled" } else { "off" }
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_and_opt_in_never_invert_device_session_locks_or_admit_a_stale_token_snapshot() {
    for gate_first in [true, false] {
        let srv = Arc::new(server!(
            |c| c.monitoring_preservation_minimum = Some(VERSION.into())
        ));
        let a = Arc::new(account(&srv, Some(VERSION)).await);
        let vault = srv.create_vault(&a).await;
        let view = probe(&srv, &a, vault.id).await;
        let gate_body = request(&vault, &view);
        let vault_id = vault.id;
        let mut held = srv.state.db.begin().await.unwrap();
        if gate_first {
            sqlx::query("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1 FOR UPDATE")
                .bind(Uuid::from(vault_id))
                .execute(&mut *held)
                .await
                .unwrap();
        } else {
            sqlx::query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE")
                .bind(Uuid::from(a.session_id))
                .execute(&mut *held)
                .await
                .unwrap();
        }
        let launch_gate = || {
            let srv = srv.clone();
            let a = a.clone();
            let body = gate_body.clone();
            tokio::spawn(async move {
                send(
                    &srv,
                    &a,
                    Method::PUT,
                    &policy_path(vault_id),
                    Some(VERSION),
                    Some(body),
                )
                .await
            })
        };
        let launch_refresh = || {
            let srv = srv.clone();
            let a = a.clone();
            tokio::spawn(async move {
                let bytes = serde_json::to_vec(&json!({"refresh_token":a.refresh})).unwrap();
                let request = srv
                    .http
                    .post(srv.url(paths::AUTH_REFRESH))
                    .header("content-type", "application/json")
                    .header(cc_protocol::version::HEADER_CLIENT_VERSION, "1.0.0")
                    .body(bytes.clone());
                srv.signed(request, &a.access, "POST", paths::AUTH_REFRESH, &bytes)
                    .send()
                    .await
                    .unwrap()
                    .status()
            })
        };
        let (gate, refresh) = if gate_first {
            let gate = launch_gate();
            wait_lock(&srv, "cc.compat.checkpoint").await;
            let refresh = launch_refresh();
            wait_lock(&srv, "cc.compat.account").await;
            (gate, refresh)
        } else {
            let refresh = launch_refresh();
            wait_lock(&srv, "FOR UPDATE OF rt, s").await;
            let gate = launch_gate();
            wait_lock(&srv, "cc.compat.account").await;
            (gate, refresh)
        };
        held.commit().await.unwrap();
        let (gate, refresh) = tokio::time::timeout(Duration::from_secs(8), async {
            (gate.await.unwrap(), refresh.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(
            refresh,
            if gate_first {
                StatusCode::UPGRADE_REQUIRED
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(
            gate.0,
            if gate_first {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        let policies: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_monitoring_compatibility WHERE user_id=$1",
        )
        .bind(Uuid::from(a.user_id))
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
        assert_eq!(policies, if gate_first { 1 } else { 0 });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_handler_rechecks_floor_after_account_wait_on_original_admitted_context() {
    let srv = Arc::new(server!(
        |c| c.monitoring_preservation_minimum = Some(VERSION.into())
    ));
    let a = Arc::new(account(&srv, Some(VERSION)).await);
    let vault = srv.create_vault(&a).await;
    let vault_id = vault.id;
    // Prove the old current version was admissible while this account was off.
    assert_eq!(
        send(
            &srv,
            &a,
            Method::GET,
            &policy_path(vault_id),
            Some("1.0.0"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    // This is the original admitted principal, not a fake policy/permission.
    // The actual handler repeats actor/token validity against real sessions.
    let mut original = common::sharing::context(&a);
    original.client_version = consolecrypt_server::compatibility::ClientVersion::parse("1.0.0");
    // A later compatible report updates the roster; old in-flight context stays old.
    let view = probe(&srv, &a, vault_id).await;
    let body = request(&vault, &view);
    let mut held = srv.state.db.begin().await.unwrap();
    sqlx::query("SELECT last_sequence FROM vault_sequences WHERE vault_id=$1 FOR UPDATE")
        .bind(Uuid::from(vault_id))
        .execute(&mut *held)
        .await
        .unwrap();
    let gate = tokio::spawn({
        let srv = srv.clone();
        let a = a.clone();
        async move {
            send(
                &srv,
                &a,
                Method::PUT,
                &policy_path(vault_id),
                Some(VERSION),
                Some(body),
            )
            .await
        }
    });
    wait_lock(&srv, "cc.compat.checkpoint").await;
    // Enter the real post-middleware handler directly to make the otherwise
    // unobservable middleware/handler scheduling gap deterministic, with no hook.
    let read = tokio::spawn({
        let state = srv.state.clone();
        async move {
            consolecrypt_server::compatibility::handlers::read(
                axum::extract::State(state),
                original,
                consolecrypt_server::extract::ApiPath(vault_id),
            )
            .await
        }
    });
    wait_lock(&srv, "cc.compat.account").await;
    held.commit().await.unwrap();
    assert_eq!(gate.await.unwrap().0, StatusCode::OK);
    let error = tokio::time::timeout(Duration::from_secs(8), read)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), cc_protocol::ErrorCode::UpgradeRequired);
    assert_eq!(probe(&srv, &a, vault_id).await["state"], "enabled");
}

#[path = "monitoring_compatibility/settings_metadata_canary.rs"]
mod settings_metadata_canary;
