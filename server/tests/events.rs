// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Realtime events over `/v1/events/ws` (PostgreSQL LISTEN/NOTIFY fanout).

mod common;

use cc_protocol::events::ServerEvent;
use cc_protocol::{paths, ObjectId};
use common::*;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn upgrade_requires_a_valid_token() {
    let srv = server!();
    assert_eq!(ws_connect(&srv, "cca_nope").await.err(), Some(401));
    let a = srv.new_account().await;
    let mut ws = ws_connect(&srv, &a.access).await.expect("upgrade");
    match ws_event(&mut ws).await {
        ServerEvent::Hello {
            session_id,
            protocol_version,
            ..
        } => {
            assert_eq!(session_id, a.session_id);
            assert_eq!(protocol_version, cc_protocol::PROTOCOL_VERSION);
        }
        other => panic!("expected hello, got {other:?}"),
    }
}

#[tokio::test]
async fn vault_changed_reaches_other_devices_but_not_other_accounts() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let b = srv.new_device_session(&a, "B").await;
    assert_eq!(srv.attest(&b, &vault).await.0, StatusCode::OK);
    let stranger = srv.new_account().await;

    let mut ws_a = ws_connect(&srv, &a.access).await.unwrap();
    let mut ws_x = ws_connect(&srv, &stranger.access).await.unwrap();
    ws_event(&mut ws_a).await; // hello
    ws_event(&mut ws_x).await; // hello

    let (status, _) = srv
        .push(
            &b,
            vault.id,
            vec![put(ObjectId::new(), 0), put(ObjectId::new(), 0)],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    match ws_event(&mut ws_a).await {
        ServerEvent::VaultChanged {
            vault_id,
            latest_sequence,
        } => {
            assert_eq!(vault_id, vault.id);
            assert_eq!(latest_sequence, 2);
        }
        other => panic!("expected vault_changed, got {other:?}"),
    }
    ws_silent(&mut ws_x, 300).await;
}

#[tokio::test]
async fn trust_request_and_approval_events() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let mut ws_a = ws_connect(&srv, &a.access).await.unwrap();
    ws_event(&mut ws_a).await; // hello

    let b = srv.new_device_session(&a, "B").await;
    assert!(
        matches!(ws_event(&mut ws_a).await, ServerEvent::DeviceAdded { device_id } if device_id == b.device.id)
    );

    let (status, body) = srv.post(paths::DEVICES, Some(&b.access), &json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let request_id: cc_protocol::DeviceRequestId =
        serde_json::from_value(body["request_id"].clone()).unwrap();
    match ws_event(&mut ws_a).await {
        ServerEvent::DeviceApprovalRequested {
            request_id: r,
            device_id,
        } => {
            assert_eq!(r, request_id);
            assert_eq!(device_id, b.device.id);
        }
        other => panic!("unexpected {other:?}"),
    }

    let (status, body) = srv
        .post(
            &device_path(paths::DEVICE_APPROVE, b.device.id),
            Some(&a.access),
            &approve_body(&a.device, request_id, &b.device, &[vault.id], now_unix()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    match ws_event(&mut ws_a).await {
        ServerEvent::DeviceApproved {
            device_id,
            vault_ids,
        } => {
            assert_eq!(device_id, b.device.id);
            assert_eq!(vault_ids, vec![vault.id]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn revoking_a_device_closes_its_socket() {
    let srv = server!();
    let a = srv.new_account().await;
    let b = srv.new_device_session(&a, "B").await;
    let mut ws_b = ws_connect(&srv, &b.access).await.unwrap();
    ws_event(&mut ws_b).await; // hello

    let (status, _) = srv
        .post(
            &device_path(paths::DEVICE_REVOKE, b.device.id),
            Some(&a.access),
            &json!({ "reason": "lost laptop" }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        matches!(ws_event(&mut ws_b).await, ServerEvent::DeviceRevoked { device_id } if device_id == b.device.id)
    );
    match ws_next(&mut ws_b).await {
        WsItem::Closed(code) => assert_eq!(code, Some(4001)),
        other => panic!("expected close, got {other:?}"),
    }
    // And it cannot reconnect.
    assert_eq!(ws_connect(&srv, &b.access).await.err(), Some(403));
}

#[tokio::test]
async fn logout_closes_the_session_socket_only() {
    let srv = server!();
    let a = srv.new_account().await;
    let b = srv.new_device_session(&a, "B").await;
    let mut ws_a = ws_connect(&srv, &a.access).await.unwrap();
    let mut ws_b = ws_connect(&srv, &b.access).await.unwrap();
    ws_event(&mut ws_a).await;
    ws_event(&mut ws_b).await;

    let (status, _) = srv
        .request::<()>(
            reqwest::Method::POST,
            paths::AUTH_LOGOUT,
            Some(&b.access),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        matches!(ws_event(&mut ws_b).await, ServerEvent::SessionRevoked { session_id } if session_id == b.session_id)
    );
    assert!(matches!(
        ws_next(&mut ws_b).await,
        WsItem::Closed(Some(4001))
    ));
    // A sees B's session_revoked but stays connected.
    assert!(matches!(
        ws_event(&mut ws_a).await,
        ServerEvent::SessionRevoked { .. }
    ));
    let vault = srv.create_vault(&a).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    assert!(matches!(
        ws_event(&mut ws_a).await,
        ServerEvent::VaultChanged { .. }
    ));
}

#[tokio::test]
async fn local_bus_works_too() {
    let srv = server!(|c| c.event_bus = consolecrypt_server::config::EventBusKind::Local);
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let mut ws = ws_connect(&srv, &a.access).await.unwrap();
    ws_event(&mut ws).await;
    srv.push(&a, vault.id, vec![put(ObjectId::new(), 0)]).await;
    assert!(matches!(
        ws_event(&mut ws).await,
        ServerEvent::VaultChanged {
            latest_sequence: 1,
            ..
        }
    ));
}

#[tokio::test]
async fn session_recheck_closes_socket_when_notification_was_missed() {
    let srv = server!(|c| c.ws_session_recheck_interval = std::time::Duration::from_millis(200));
    let a = srv.new_account().await;
    let mut ws = ws_connect(&srv, &a.access).await.unwrap();
    ws_event(&mut ws).await;
    // Revoke directly in the DB: no event is published.
    sqlx::query("UPDATE sessions SET revoked_at = now()")
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert!(matches!(ws_next(&mut ws).await, WsItem::Closed(Some(4001))));
}

#[tokio::test]
async fn websocket_connections_per_account_are_capped() {
    let srv = server!(|c| c.ws_max_connections_per_user = 2);
    let a = srv.new_account().await;
    let mut first = ws_connect(&srv, &a.access).await.unwrap();
    let _second = ws_connect(&srv, &a.access).await.unwrap();
    ws_event(&mut first).await;
    assert_eq!(ws_connect(&srv, &a.access).await.err(), Some(429));
    // Another account is unaffected.
    let b = srv.new_account().await;
    assert!(ws_connect(&srv, &b.access).await.is_ok());
    // Closing one frees a slot.
    drop(first);
    // The server notices the close asynchronously; retry for a while.
    let mut reconnected = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if ws_connect(&srv, &a.access).await.is_ok() {
            reconnected = true;
            break;
        }
    }
    assert!(reconnected, "slot was not released after close");
}

#[tokio::test]
async fn socket_closes_when_its_access_token_is_rotated() {
    let srv = server!(|c| c.ws_session_recheck_interval = std::time::Duration::from_millis(200));
    let a = srv.new_account().await;
    let mut ws = ws_connect(&srv, &a.access).await.unwrap();
    ws_event(&mut ws).await;
    let (s, _) = srv
        .post(
            paths::AUTH_REFRESH,
            None,
            &json!({ "refresh_token": a.refresh }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    match ws_next(&mut ws).await {
        WsItem::Closed(code) => assert_eq!(code, Some(cc_protocol::events::CLOSE_TOKEN_EXPIRED)),
        other => panic!("expected close 4003, got {other:?}"),
    }
}

#[tokio::test]
async fn concurrent_upgrades_cannot_exceed_the_cap() {
    let srv = server!(|c| c.ws_max_connections_per_user = 2);
    let a = srv.new_account().await;
    let attempts = (0..8).map(|_| ws_connect(&srv, &a.access));
    let results = futures_util::future::join_all(attempts).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert!(ok <= 2, "{ok} sockets opened with a cap of 2");
    assert!(results.iter().any(|r| r.as_ref().err() == Some(&429)));
}

#[tokio::test]
async fn database_failure_closes_event_stream_with_transient_server_error() {
    let srv = server!(|c| c.ws_session_recheck_interval = std::time::Duration::from_millis(100));
    let account = srv.new_account().await;
    let mut ws = ws_connect(&srv, &account.access).await.unwrap();
    ws_event(&mut ws).await;
    // Make only this fixture's session lookup fail. Closing its pool would
    // wait for the separately held LISTEN connection and deadlock the test.
    sqlx::query("ALTER TABLE sessions RENAME TO unavailable_sessions")
        .execute(&srv.state.db)
        .await
        .unwrap();
    assert!(matches!(ws_next(&mut ws).await, WsItem::Closed(Some(1011))));
}
