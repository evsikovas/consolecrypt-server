// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Vault lifecycle, envelopes and vault recovery (ADR-0004 recovery flows).

mod common;

use cc_protocol::envelopes::KeyEnvelope;
use cc_protocol::events::ServerEvent;
use cc_protocol::recovery::VaultRecoveryMaterial;
use cc_protocol::{paths, ObjectId};
use common::*;
use reqwest::StatusCode;
use serde_json::json;

fn material_path(v: cc_protocol::VaultId) -> String {
    format!("{}?vault_id={v}", paths::RECOVERY_VAULT_ENVELOPE)
}

#[tokio::test]
async fn create_vault_validation() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = TestVault::new();

    let mut req = serde_json::to_value(vault.create_request(a.device.id)).unwrap();
    req["vault_access_key"] = json!(cc_protocol::Bytes::new(vec![1; 16]));
    assert_eq!(
        srv.post(paths::VAULTS, Some(&a.access), &req).await.0,
        StatusCode::BAD_REQUEST
    );

    // Device envelope for another device.
    let mut r = vault.create_request(a.device.id);
    r.device_envelope = device_envelope(cc_protocol::DeviceId::new());
    assert_eq!(
        srv.post(paths::VAULTS, Some(&a.access), &r).await.0,
        StatusCode::BAD_REQUEST
    );

    // Weak KDF parameters below the server floor.
    let mut r = vault.create_request(a.device.id);
    r.password_envelope
        .metadata
        .kdf
        .as_mut()
        .unwrap()
        .memory_kib = 1024;
    let (s, body) = srv.post(paths::VAULTS, Some(&a.access), &r).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");

    // Envelopes swapped.
    let mut r = vault.create_request(a.device.id);
    std::mem::swap(&mut r.password_envelope, &mut r.recovery_envelope);
    assert_eq!(
        srv.post(paths::VAULTS, Some(&a.access), &r).await.0,
        StatusCode::BAD_REQUEST
    );

    // Valid, then duplicate id → 409.
    let r = vault.create_request(a.device.id);
    assert_eq!(
        srv.post(paths::VAULTS, Some(&a.access), &r).await.0,
        StatusCode::CREATED
    );
    let (s, body) = srv.post(paths::VAULTS, Some(&a.access), &r).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["code"], "already_exists");
    assert_eq!(body["details"]["field"], "vault_id");
}

#[tokio::test]
async fn recovery_material_by_trust_level() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;

    let (s, body) = srv.get(&material_path(vault.id), &b.access).await;
    assert_eq!(s, StatusCode::OK);
    let m: VaultRecoveryMaterial = serde_json::from_value(body).unwrap();
    assert!(m.password_envelope.is_some() && m.recovery_envelope.is_some());
    assert!(m.device_envelope.is_none());

    let (_, body) = srv.get(&material_path(vault.id), &a.access).await;
    let m: VaultRecoveryMaterial = serde_json::from_value(body).unwrap();
    let own = m.device_envelope.unwrap();
    assert_eq!(own.recipient_id, Some(a.device.id.into()));
    assert_eq!(own.created_by_device_id, Some(a.device.id));
}

#[tokio::test]
async fn replace_password_envelope_after_forgotten_passphrase() {
    // "Forgot vault passphrase, have a trusted device": device envelope →
    // VRK → new passphrase → replace (T + K).
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    let mut ws = ws_connect(&srv, &b.access).await.unwrap();
    ws_event(&mut ws).await;
    let (_, body) = srv.get(&material_path(vault.id), &a.access).await;
    let before: VaultRecoveryMaterial = serde_json::from_value(body).unwrap();

    let replace = |token: String,
                   vak: cc_protocol::Bytes,
                   env: cc_protocol::envelopes::NewEnvelope,
                   path: &'static str| {
        let srv = &srv;
        let vault_id = vault.id;
        async move {
            srv.post(
                path,
                Some(&token),
                &json!({"vault_id": vault_id, "vault_access_key": vak, "envelope": env}),
            )
            .await
        }
    };

    // Untrusted device B → 403; wrong key → 422; wrong type → 400.
    let (s, _) = replace(
        b.access.clone(),
        vault.vak_bytes(),
        password_envelope(),
        paths::RECOVERY_VAULT_PASSWORD_REPLACE,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, body) = replace(
        a.access.clone(),
        cc_protocol::Bytes::new(random::<32>().to_vec()),
        password_envelope(),
        paths::RECOVERY_VAULT_PASSWORD_REPLACE,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (s, _) = replace(
        a.access.clone(),
        vault.vak_bytes(),
        recovery_envelope(),
        paths::RECOVERY_VAULT_PASSWORD_REPLACE,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, body) = replace(
        a.access.clone(),
        vault.vak_bytes(),
        password_envelope(),
        paths::RECOVERY_VAULT_PASSWORD_REPLACE,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let new_env: KeyEnvelope = serde_json::from_value(body).unwrap();
    assert_ne!(
        Some(new_env.envelope_id),
        before.password_envelope.as_ref().map(|e| e.envelope_id)
    );

    let (_, body) = srv.get(&material_path(vault.id), &b.access).await;
    let after: VaultRecoveryMaterial = serde_json::from_value(body).unwrap();
    assert_eq!(
        after.password_envelope.unwrap().envelope_id,
        new_env.envelope_id
    );
    // Exactly one live password envelope; the old one is kept revoked.
    assert_eq!(
        srv.db_scalar_i64("SELECT count(*) FROM vault_key_envelopes WHERE recipient_type = 'password' AND revoked_at IS NULL").await,
        1
    );
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM vault_key_envelopes WHERE recipient_type = 'password'"
        )
        .await,
        2
    );
    match ws_event(&mut ws).await {
        ServerEvent::RecoveryChanged {
            vault_id,
            recipient_type,
        } => {
            assert_eq!(vault_id, vault.id);
            assert_eq!(
                recipient_type,
                cc_protocol::envelopes::RecipientType::Password
            );
        }
        other => panic!("unexpected {other:?}"),
    }

    // Regenerate the Recovery Key.
    let (s, _) = replace(
        a.access.clone(),
        vault.vak_bytes(),
        recovery_envelope(),
        paths::RECOVERY_VAULT_RECOVERY_REPLACE,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'envelope_replaced'"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn recovery_key_restore_on_new_device() {
    // "No trusted device, have Recovery Key": new device logs in, downloads
    // the recovery envelope, unlocks locally, attests with VAK, replaces the
    // password envelope, syncs.
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    // All trusted devices are gone.
    srv.request::<()>(
        reqwest::Method::POST,
        &device_path(paths::DEVICE_REVOKE, a.device.id),
        Some(&a.access),
        None,
    )
    .await;

    let fresh = TestDevice::new("replacement laptop");
    let (s, body) = srv.login(&a.email, &a.password, &fresh).await;
    assert_eq!(s, StatusCode::OK);
    let n = srv.session(a.email.clone(), a.password.clone(), fresh, body);
    let (_, body) = srv.get(&material_path(vault.id), &n.access).await;
    let m: VaultRecoveryMaterial = serde_json::from_value(body).unwrap();
    assert!(m.recovery_envelope.is_some());
    assert_eq!(srv.attest(&n, &vault).await.0, StatusCode::OK);
    let (s, _) = srv
        .post(
            paths::RECOVERY_VAULT_PASSWORD_REPLACE,
            Some(&n.access),
            &json!({"vault_id": vault.id, "vault_access_key": vault.vak_bytes(), "envelope": password_envelope()}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = srv.changes(&n, vault.id, 0).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["changes"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn envelope_create_and_delete_rules() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    let envs_path = paths::fill(
        paths::VAULT_ENVELOPES,
        &[("vault_id", &vault.id.to_string())],
    );

    // Trusted A sees all 4 live envelopes (password, recovery, A, B).
    let (_, body) = srv.get(&envs_path, &a.access).await;
    let envs: Vec<KeyEnvelope> = serde_json::from_value(body["envelopes"].clone()).unwrap();
    assert_eq!(envs.len(), 4);

    // Re-key own device envelope: OK. Envelope for another device: 400.
    let (s, body) = srv
        .post(&envs_path, Some(&a.access), &json!({"vault_access_key": vault.vak_bytes(), "envelope": device_envelope(a.device.id)}))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let (s, _) = srv
        .post(&envs_path, Some(&a.access), &json!({"vault_access_key": vault.vak_bytes(), "envelope": device_envelope(b.device.id)}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = srv
        .post(
            &envs_path,
            Some(&a.access),
            &json!({"vault_access_key": vault.vak_bytes(), "envelope": password_envelope()}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Password envelope cannot be deleted; B's device envelope can (B loses trust).
    let password = envs
        .iter()
        .find(|e| e.recipient_type == cc_protocol::envelopes::RecipientType::Password)
        .unwrap();
    let b_env = envs
        .iter()
        .find(|e| e.recipient_id == Some(b.device.id.into()))
        .unwrap();
    let env_path = |id: cc_protocol::EnvelopeId| {
        paths::fill(
            paths::VAULT_ENVELOPE,
            &[
                ("vault_id", &vault.id.to_string()),
                ("envelope_id", &id.to_string()),
            ],
        )
    };
    let (s, _) = srv
        .delete(
            &env_path(password.envelope_id),
            &a.access,
            Some(&json!({"vault_access_key": vault.vak_bytes()})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = srv
        .delete::<()>(&env_path(b_env.envelope_id), &a.access, None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "vault access key required");
    let (s, _) = srv
        .delete(
            &env_path(b_env.envelope_id),
            &a.access,
            Some(&json!({"vault_access_key": vault.vak_bytes()})),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(srv.changes(&b, vault.id, 0).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_vault() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let path = paths::fill(paths::VAULT, &[("vault_id", &vault.id.to_string())]);

    let (s, _) = srv.delete::<()>(&path, &a.access, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = srv
        .delete(
            &path,
            &a.access,
            Some(&json!({"vault_access_key": cc_protocol::Bytes::new(random::<32>().to_vec())})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = srv
        .delete(
            &path,
            &a.access,
            Some(&json!({"vault_access_key": vault.vak_bytes()})),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, body) = srv.get(&path, &a.access).await;
    assert_eq!(s, StatusCode::GONE);
    assert_eq!(body["code"], "gone");
    assert_eq!(srv.changes(&a, vault.id, 0).await.0, StatusCode::GONE);
    assert_eq!(
        srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)])
            .await
            .0,
        StatusCode::GONE
    );
    let (_, body) = srv.get(paths::VAULTS, &a.access).await;
    assert!(body["vaults"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn vault_epoch_is_stable_until_rotated_after_restore() {
    use cc_protocol::sync::{ChangesResponse, SnapshotResponse};
    use cc_protocol::vaults::VaultInfo;
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let vault_path = paths::fill(paths::VAULT, &[("vault_id", &vault.id.to_string())]);

    let (_, body) = srv.get(&vault_path, &a.access).await;
    let info: VaultInfo = serde_json::from_value(body).unwrap();
    let epoch = info.epoch.expect("epoch");
    let (_, body) = srv.changes(&a, vault.id, 0).await;
    let c: ChangesResponse = serde_json::from_value(body).unwrap();
    assert_eq!(c.epoch, Some(epoch));
    let (_, body) = srv
        .get(
            &format!("{}?vault_id={}", paths::SYNC_SNAPSHOT, vault.id),
            &a.access,
        )
        .await;
    let s: SnapshotResponse = serde_json::from_value(body).unwrap();
    assert_eq!(s.epoch, Some(epoch));
    let (_, body) = srv.get(paths::VAULTS, &a.access).await;
    assert_eq!(body["vaults"][0]["epoch"], epoch.to_string());

    // Operator restored a backup and rotates the epoch; connected clients are nudged.
    let mut ws = ws_connect(&srv, &a.access).await.unwrap();
    ws_event(&mut ws).await;
    let n = consolecrypt_server::admin::rotate_epoch(&srv.state.db, Some(vault.id))
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(
        matches!(ws_event(&mut ws).await, ServerEvent::VaultChanged { vault_id, .. } if vault_id == vault.id)
    );
    let (_, body) = srv.get(&vault_path, &a.access).await;
    let info: VaultInfo = serde_json::from_value(body).unwrap();
    assert_ne!(info.epoch, Some(epoch));
    assert!(consolecrypt_server::admin::rotate_epoch(
        &srv.state.db,
        Some(cc_protocol::VaultId::new())
    )
    .await
    .is_err());
}
