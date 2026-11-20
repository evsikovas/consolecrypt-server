//! Actual default-off legacy report preservation; not header attestation.
mod common;
use cc_protocol::{paths, VaultId};
use common::*;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;
const CURRENT: &str = "2.0.0"; // synthetic ONLY; no declared shipped floor.
async fn get(
    srv: &TestServer,
    endpoint: &TestServer,
    who: &Session,
    path: &str,
    version: &str,
) -> (StatusCode, Value) {
    let request = srv
        .http
        .get(endpoint.url(path))
        .bearer_auth(&who.access)
        .header(cc_protocol::version::HEADER_CLIENT_VERSION, version);
    let response = srv
        .signed(request, &who.access, "GET", path, b"")
        .send()
        .await
        .unwrap();
    (response.status(), response.json().await.unwrap())
}
fn policy(vault: VaultId) -> String {
    format!("/v1/vaults/{vault}/compatibility/monitoring-settings")
}
#[tokio::test]
async fn default_off_prerelease_and_custom_reports_replace_old_stable_and_block_roster_opt_in() {
    let srv = server!(|config| config.monitoring_preservation_minimum = Some(CURRENT.into()));
    let owner = srv.new_account().await;
    let device = srv
        .new_device_session(&owner, "Owned reported version")
        .await;
    let vault = srv.create_vault(&owner).await;
    assert_eq!(
        get(&srv, &srv, &owner, &policy(vault.id), CURRENT).await.0,
        StatusCode::OK
    );
    for report in ["2.1.0-beta.1", "custom-preview"] {
        // A real fresh replica has an empty legitimate observation throttle;
        // isolate stable parsing from the existing five-minute touch cache.
        let stable = srv.replica(|_| {}).await;
        assert_eq!(
            get(&srv, &stable, &device, paths::DEVICES, CURRENT).await.0,
            StatusCode::OK
        );
        let observed = srv.replica(|_| {}).await;
        assert_eq!(
            get(&srv, &observed, &device, paths::DEVICES, report)
                .await
                .0,
            StatusCode::OK
        );
        let actual: Option<String> =
            sqlx::query_scalar("SELECT client_version FROM devices WHERE id=$1")
                .bind(Uuid::from(device.device.id))
                .fetch_one(&srv.state.db)
                .await
                .unwrap();
        assert_eq!(actual.as_deref(), Some(report));
        let (status, view) = get(&srv, &srv, &owner, &policy(vault.id), CURRENT).await;
        assert_eq!(status, StatusCode::OK);
        let body = serde_json::to_vec(&json!({"version":1,"expectedRevision":view["revision"],
            "expectedRosterDigest":view["rosterDigest"],"vaultAccessKey":vault.vak_bytes()}))
        .unwrap();
        let path = policy(vault.id);
        let request = srv
            .http
            .request(Method::PUT, srv.url(&path))
            .bearer_auth(&owner.access)
            .header(cc_protocol::version::HEADER_CLIENT_VERSION, CURRENT)
            .header("content-type", "application/json")
            .body(body.clone());
        let response = srv
            .signed(request, &owner.access, "PUT", &path, &body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_monitoring_compatibility WHERE user_id=$1",
        )
        .bind(Uuid::from(owner.user_id))
        .fetch_one(&srv.state.db)
        .await
        .unwrap();
        assert_eq!(rows, 0);
    }
}

#[tokio::test]
async fn opted_account_checks_current_report_without_erasing_last_known_metadata() {
    let srv = server!(|config| config.monitoring_preservation_minimum = Some(CURRENT.into()));
    let owner = srv.new_account().await;
    let device = srv.new_device_session(&owner, "Owned active report").await;
    let vault = srv.create_vault(&owner).await;
    let stable = srv.replica(|_| {}).await;
    assert_eq!(
        get(&srv, &stable, &device, paths::DEVICES, CURRENT).await.0,
        StatusCode::OK
    );
    let (status, view) = get(&srv, &srv, &owner, &policy(vault.id), CURRENT).await;
    assert_eq!(status, StatusCode::OK);
    let path = policy(vault.id);
    let body = serde_json::to_vec(&json!({"version":1,"expectedRevision":view["revision"],
        "expectedRosterDigest":view["rosterDigest"],"vaultAccessKey":vault.vak_bytes()}))
    .unwrap();
    let request = srv
        .http
        .request(Method::PUT, srv.url(&path))
        .bearer_auth(&owner.access)
        .header(cc_protocol::version::HEADER_CLIENT_VERSION, CURRENT)
        .header("content-type", "application/json")
        .body(body.clone());
    assert_eq!(
        srv.signed(request, &owner.access, "PUT", &path, &body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let oversize = "9".repeat(65);
    for report in [
        Some("2.1.0-beta.1"),
        Some("custom-preview"),
        None,
        Some(oversize.as_str()),
    ] {
        let mut request = srv
            .http
            .get(srv.url(paths::DEVICES))
            .bearer_auth(&device.access);
        if let Some(report) = report {
            request = request.header(cc_protocol::version::HEADER_CLIENT_VERSION, report);
        }
        let response = srv
            .signed(request, &device.access, "GET", paths::DEVICES, b"")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        // A refused request must not change the last known display metadata.
        // It never falls back to this stored value for current admission.
        let stored: Option<String> =
            sqlx::query_scalar("SELECT client_version FROM devices WHERE id=$1")
                .bind(Uuid::from(device.device.id))
                .fetch_one(&srv.state.db)
                .await
                .unwrap();
        assert_eq!(stored.as_deref(), Some(CURRENT));
    }
    assert_eq!(
        get(&srv, &srv, &device, paths::DEVICES, CURRENT).await.0,
        StatusCode::OK
    );
}
