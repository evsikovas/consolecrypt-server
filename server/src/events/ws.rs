// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `GET /v1/events/ws` — WebSocket event stream (principal A).
//!
//! Close codes (application range):
//! * `4001` — session or device revoked / expired: refresh or log in again,
//!   do not reconnect with the same access token;
//! * `4002` — the connection fell behind: reconnect and pull.

use crate::auth::AuthContext;
use crate::state::AppState;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use cc_protocol::events::{ServerEvent, CLOSE_LAGGED, CLOSE_REVOKED, CLOSE_TOKEN_EXPIRED};
use cc_protocol::PROTOCOL_VERSION;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

/// Clients never need to send more than control frames.
const MAX_CLIENT_MESSAGE: usize = 4 * 1024;

pub async fn events_ws(
    State(state): State<AppState>,
    auth: AuthContext,
    ws: WebSocketUpgrade,
) -> Response {
    // Bound resources per account (per replica): a stolen token must not be
    // able to pin unbounded sockets.
    let Some(slot) = state
        .events
        .try_reserve_slot(auth.user_id, state.config.ws_max_connections_per_user)
    else {
        return crate::error::AppError::rate_limited(10).into_response();
    };
    ws.max_message_size(MAX_CLIENT_MESSAGE)
        .max_frame_size(MAX_CLIENT_MESSAGE)
        .on_upgrade(move |socket| async move {
            run(socket, state, auth).await;
            drop(slot);
        })
}

struct ConnectionGauge;

impl ConnectionGauge {
    fn new() -> Self {
        metrics::gauge!("cc_ws_connections").increment(1.0);
        ConnectionGauge
    }
}

impl Drop for ConnectionGauge {
    fn drop(&mut self) {
        metrics::gauge!("cc_ws_connections").decrement(1.0);
    }
}

/// A client that stops reading must not pin the connection task forever.
const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn send_message(socket: &mut WebSocket, message: Message) -> Result<(), ()> {
    match tokio::time::timeout(SEND_TIMEOUT, socket.send(message)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

async fn send_event(socket: &mut WebSocket, event: &ServerEvent) -> Result<(), ()> {
    let text = serde_json::to_string(event).map_err(|_| ())?;
    send_message(socket, Message::Text(text.into())).await
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let _ = send_message(
        socket,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
    )
    .await;
}

async fn run(mut socket: WebSocket, state: AppState, auth: AuthContext) {
    // Subscribe before greeting so nothing published after `hello` is missed.
    let mut rx = state.events.subscribe(auth.user_id);
    let _gauge = ConnectionGauge::new();
    tracing::debug!(user_id = %auth.user_id, device_id = %auth.device_id, "websocket connected");

    let hello = ServerEvent::Hello {
        protocol_version: PROTOCOL_VERSION,
        server_time: chrono::Utc::now(),
        session_id: auth.session_id,
    };
    if send_event(&mut socket, &hello).await.is_err() {
        return;
    }

    let mut ping = tokio::time::interval(state.config.ws_ping_interval);
    ping.tick().await;
    let mut recheck = tokio::time::interval(state.config.ws_session_recheck_interval);
    recheck.tick().await;

    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    if send_event(&mut socket, &ev).await.is_err() {
                        break;
                    }
                    let ends_connection = match &*ev {
                        ServerEvent::SessionRevoked { session_id } => *session_id == auth.session_id,
                        ServerEvent::DeviceRevoked { device_id } => *device_id == auth.device_id,
                        _ => false,
                    };
                    if ends_connection {
                        close(&mut socket, CLOSE_REVOKED, "revoked").await;
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    close(&mut socket, CLOSE_LAGGED, "lagged; reconnect and pull").await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                // Pings are answered by the protocol layer; data frames ignored.
                Some(Ok(_)) => {}
            },
            _ = ping.tick() => {
                if send_message(&mut socket, Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
            _ = recheck.tick() => match session_state(&state, &auth).await {
                SessionState::Live => {}
                SessionState::TokenExpired => {
                    close(&mut socket, CLOSE_TOKEN_EXPIRED, "access token expired or rotated").await;
                    break;
                }
                SessionState::Revoked => {
                    close(&mut socket, CLOSE_REVOKED, "session no longer valid").await;
                    break;
                }
                SessionState::Unavailable => {
                    // Standard transient server failure: reconnect later,
                    // without treating a database outage as account revocation.
                    close(&mut socket, 1011, "session validation unavailable").await;
                    break;
                }
            },
        }
    }
    tracing::debug!(user_id = %auth.user_id, "websocket closed");
}

enum SessionState {
    Live,
    /// Session fine, but the token this socket was opened with is no longer
    /// current (expired or rotated): the client reconnects with its new one.
    TokenExpired,
    Revoked,
    Unavailable,
}

/// Periodic safety net in case a revocation notification was lost, and the
/// bound on how long a (possibly stolen) access token keeps a socket open.
/// Stop delivering metadata when authorization cannot be revalidated.
/// An unavailable database must not extend a revoked/expired session forever.
async fn session_state(state: &AppState, auth: &AuthContext) -> SessionState {
    let row: Result<Option<(bool, bool)>, _> = sqlx::query_as(
        "SELECT s.revoked_at IS NULL AND d.revoked_at IS NULL
                AND s.expires_at > now() AND u.status = 'active',
                s.access_token_hash = $2 AND s.access_expires_at > now()
           FROM sessions s
           JOIN devices d ON d.id = s.device_id
           JOIN users u ON u.id = s.user_id
          WHERE s.id = $1",
    )
    .bind(Uuid::from(auth.session_id))
    .bind(&auth.access_token_hash[..])
    .fetch_optional(&state.db)
    .await;
    match row {
        Ok(Some((true, true))) => SessionState::Live,
        Ok(Some((true, false))) => SessionState::TokenExpired,
        Ok(_) => SessionState::Revoked,
        Err(err) => {
            tracing::warn!(
                failure = crate::error::database_error_kind(&err),
                "websocket session re-check failed"
            );
            SessionState::Unavailable
        }
    }
}
