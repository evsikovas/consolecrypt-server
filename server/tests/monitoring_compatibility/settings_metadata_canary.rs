//! Real HTTP + owned PostgreSQL canary for the account-wide opaque-object gate.
//! Client crypto/metadata semantics are tested separately in actual AppCore sync.
//! Production keeps the operator offer off unless explicitly configured.
use super::*;
use cc_protocol::sync::{ChangesResponse, MutationOp, PushResponse};

#[tokio::test]
async fn project_settings_sync_reaches_a_second_trusted_1_2_client() {
    const MINIMUM: &str = "1.2.0";
    const DESKTOP: &str = "1.2.0+67035";
    let srv = server!(|config| config.monitoring_preservation_minimum = Some(MINIMUM.into()));
    let desktop = account(&srv, Some(DESKTOP)).await;
    let vault = srv.create_vault(&desktop).await;
    let device = TestDevice::new("Second 1.2 client");
    let mut registration = serde_json::to_value(device.registration()).unwrap();
    registration["client_version"] = json!(MINIMUM);
    let (status, body) = srv
        .post(
            paths::AUTH_LOGIN,
            None,
            &json!({
                "email": desktop.email,
                "password": desktop.password,
                "device": registration,
                "device_proof": device.proof(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let second = srv.session(
        desktop.email.clone(),
        desktop.password.clone(),
        device,
        body,
    );
    assert_eq!(srv.attest(&second, &vault).await.0, StatusCode::OK);

    let policy = policy_path(vault.id);
    let (status, offer) = send(&srv, &desktop, Method::GET, &policy, Some(DESKTOP), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(offer["state"], "off");
    assert_eq!(offer["offerMinimumClientVersion"], MINIMUM);
    let (status, enabled) = send(
        &srv,
        &desktop,
        Method::PUT,
        &policy,
        Some(DESKTOP),
        Some(request(&vault, &offer)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(enabled["state"], "enabled");
    assert_eq!(enabled["minimumClientVersion"], MINIMUM);
    let (status, observed) = send(&srv, &second, Method::GET, &policy, Some(MINIMUM), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(observed["revision"], enabled["revision"]);
    assert_eq!(observed["checkpoint"], enabled["checkpoint"]);
    let after = observed["checkpoint"]["vaultSequence"].as_i64().unwrap();

    // The server transports the encrypted VaultSettings object the same way
    // as other vault objects. Its schema and contents are only known to clients.
    let id = ObjectId::new();
    let settings = put(id, 0);
    let MutationOp::Put { body: expected } = settings.op.clone() else {
        unreachable!();
    };
    let (status, pushed) = mutation(&srv, &desktop, vault.id, Some(DESKTOP), settings).await;
    assert_eq!(status, StatusCode::OK);
    let pushed: PushResponse = serde_json::from_value(pushed).unwrap();
    assert_eq!(pushed.latest_sequence, after + 1);

    let changes_path = format!(
        "{}?vault_id={}&after={after}",
        paths::SYNC_CHANGES,
        vault.id
    );
    let (status, received) = send(
        &srv,
        &second,
        Method::GET,
        &changes_path,
        Some(MINIMUM),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let received: ChangesResponse = serde_json::from_value(received).unwrap();
    assert_eq!(received.changes.len(), 1);
    let change = &received.changes[0];
    assert_eq!(change.object_id, id);
    assert_eq!(change.writer_device_id, desktop.device.id);
    assert_eq!(change.body.as_ref(), Some(&expected));
    assert_eq!(change.revision, 1);
    assert_eq!(received.next_after, pushed.latest_sequence);

    assert_eq!(
        mutation(&srv, &desktop, vault.id, Some("1.1.3"), put(id, 1))
            .await
            .0,
        StatusCode::UPGRADE_REQUIRED
    );
    assert_eq!(count(&srv, vault.id).await, received.next_after);
}

type Stored = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
async fn stored(srv: &TestServer, vault: VaultId, id: ObjectId) -> Stored {
    sqlx::query_as("SELECT revision,ciphertext,nonce,wrapped_dek,wrapped_dek_nonce FROM vault_objects WHERE vault_id=$1 AND object_id=$2")
        .bind(Uuid::from(vault)).bind(Uuid::from(id)).fetch_one(&srv.state.db).await.unwrap()
}
async fn mutation(
    srv: &TestServer,
    a: &Session,
    vault: VaultId,
    version: Option<&str>,
    item: cc_protocol::sync::Mutation,
) -> (StatusCode, Value) {
    send(
        srv,
        a,
        Method::POST,
        paths::SYNC_PUSH,
        version,
        Some(json!({"vault_id":vault,"device_id":a.device.id,"mutations":[item]})),
    )
    .await
}
#[tokio::test]
#[ignore = "explicit owned HTTP/PostgreSQL canary; CC_TEST_REQUIRE_DB=1 required"]
async fn one_explicit_account_floor_protects_mon07_and_ans04_ciphertext_without_reading_payloads() {
    assert_eq!(
        std::env::var("CC_TEST_REQUIRE_DB").ok().as_deref(),
        Some("1"),
        "canary must fail rather than skip when owned DB is unavailable"
    );
    let off = server!();
    let legacy = account(&off, None).await;
    let vault = off.create_vault(&legacy).await;
    let view = probe(&off, &legacy, vault.id).await;
    assert_eq!(view["state"], "off");
    assert!(view["offerMinimumClientVersion"].is_null());
    assert_eq!(
        mutation(&off, &legacy, vault.id, None, put(ObjectId::new(), 0))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &off,
            &legacy,
            Method::PUT,
            &policy_path(vault.id),
            Some(VERSION),
            Some(request(&vault, &view))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // This exact server offer is test-owned, not a shipped preservation floor.
    let srv = server!(|c| c.monitoring_preservation_minimum = Some(VERSION.into()));
    let a = account(&srv, Some(VERSION)).await;
    let vault = srv.create_vault(&a).await;
    enable(&srv, &a, &vault).await;
    let id = ObjectId::new();
    assert_eq!(
        mutation(&srv, &a, vault.id, Some(VERSION), put(id, 0))
            .await
            .0,
        StatusCode::OK
    );
    let original = stored(&srv, vault.id, id).await;
    let sequence = count(&srv, vault.id).await;
    for old in [None, Some("1.9.9"), Some("2.0.0-beta.1")] {
        assert_eq!(
            mutation(&srv, &a, vault.id, old, put(id, 1)).await.0,
            StatusCode::UPGRADE_REQUIRED
        );
        assert_eq!(
            mutation(&srv, &a, vault.id, old, delete(id, 1)).await.0,
            StatusCode::UPGRADE_REQUIRED
        );
        assert_eq!(stored(&srv, vault.id, id).await, original);
        assert_eq!(count(&srv, vault.id).await, sequence);
    }
    // Removing offer config cannot remove the actual persisted floor.
    let replica = srv
        .replica(|c| c.monitoring_preservation_minimum = None)
        .await;
    for version in [None, Some("1.9.9"), Some("2.0.0-beta.1")] {
        for item in [put(id, 1), delete(id, 1)] {
            let bytes = serde_json::to_vec(
                &json!({"vault_id":vault.id,"device_id":a.device.id,"mutations":[item]}),
            )
            .unwrap();
            let mut request = replica
                .http
                .post(replica.url(paths::SYNC_PUSH))
                .bearer_auth(&a.access)
                .header("content-type", "application/json")
                .body(bytes.clone());
            if let Some(version) = version {
                request = request.header(cc_protocol::version::HEADER_CLIENT_VERSION, version);
            }
            // Original actual signer, same account/DB, different real server
            // whose operator offer is OFF. No missing request-proof shortcut.
            let response = srv
                .signed(request, &a.access, "POST", paths::SYNC_PUSH, &bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
            assert_eq!(stored(&srv, vault.id, id).await, original);
            assert_eq!(count(&srv, vault.id).await, sequence);
        }
    }
    assert_eq!(
        mutation(&srv, &a, vault.id, Some(VERSION), put(id, 1))
            .await
            .0,
        StatusCode::OK
    );
    let updated = stored(&srv, vault.id, id).await;
    assert_eq!(updated.0, 2);
    assert_ne!(updated.1, original.1);
}
