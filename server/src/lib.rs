// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! ConsoleCrypt Cloud/Sync server.
//!
//! A zero-knowledge sync server: it stores ciphertext, key envelopes, public
//! keys and non-secret metadata, authenticates accounts and devices, orders
//! changes per vault and notifies clients. It has no code path and no key to
//! decrypt vault data (`docs/security/THREAT_MODEL.md`), and it never carries
//! SSH traffic.
//!
//! Wire contract: `cc-protocol` (`crates/protocol`). Architecture:
//! `SERVER_ARCHITECTURE.md`. License: AGPL-3.0-only.

pub mod admin;
pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod devices;
pub mod error;
pub mod events;
pub mod extract;
pub mod jobs;
pub mod mail;
pub mod meta;
pub mod middleware;
pub mod ratelimit;
pub mod recovery;
pub mod state;
pub mod sync;
pub mod telemetry;
pub mod util;
pub mod vaults;
pub mod web;

pub use config::Config;
pub use state::AppState;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware as axum_mw, Router};
use cc_protocol::{limits, paths};
use std::net::SocketAddr;
use tower_http::catch_panic::CatchPanicLayer;

/// Default request body limit (everything except push and public auth).
pub const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;
/// Body limit of the public (unauthenticated) auth endpoints.
pub const AUTH_BODY_LIMIT: usize = 64 * 1024;
/// Whole-request timeout (includes reading the body). WebSocket upgrades
/// return immediately, so live sockets are not affected.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The complete HTTP application.
pub fn build_router(state: AppState) -> Router {
    use auth::handlers as a;
    use devices::handlers as d;
    use sync::handlers as s;
    use vaults::handlers as v;

    // Public auth endpoints carry tiny bodies: a small limit bounds what an
    // unauthenticated client can make the server buffer.
    let auth_public = Router::new()
        .route(paths::AUTH_REGISTER, post(a::register))
        .route(paths::AUTH_LOGIN, post(a::login))
        .route(paths::AUTH_REFRESH, post(a::refresh))
        .route(paths::AUTH_PASSWORD_FORGOT, post(a::forgot_password))
        .route(paths::AUTH_PASSWORD_RESET, post(a::reset_password))
        .route(paths::AUTH_EMAIL_VERIFY, post(a::verify_email))
        .route(paths::RECOVERY_ACCOUNT_START, post(a::recovery_start))
        .route(paths::RECOVERY_ACCOUNT_CONFIRM, post(a::recovery_confirm))
        .layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT));

    // Everything below requires principal A: bearer token + (protocol 1.5)
    // per-request device proof, established by `auth::middleware`.
    let authed = Router::new()
        // auth (authenticated)
        .route(paths::AUTH_LOGOUT, post(a::logout))
        .route(paths::AUTH_ME, get(a::me))
        .route(paths::AUTH_PASSWORD_CHANGE, post(a::change_password))
        // devices
        .route(
            paths::DEVICES,
            get(d::list_devices).post(d::create_trust_request),
        )
        .route(paths::DEVICE, axum::routing::patch(d::rename_device))
        .route(paths::DEVICE_APPROVE, post(d::approve_device))
        .route(paths::DEVICE_REJECT, post(d::reject_device))
        .route(paths::DEVICE_ATTEST, post(d::attest_device))
        .route(paths::DEVICE_REVOKE, post(d::revoke_device))
        // vaults
        .route(paths::VAULTS, get(v::list_vaults).post(v::create_vault))
        .route(paths::VAULT, get(v::get_vault).delete(v::delete_vault))
        .route(
            paths::VAULT_ENVELOPES,
            get(v::list_envelopes).post(v::create_envelope),
        )
        .route(
            paths::VAULT_ENVELOPE,
            axum::routing::delete(v::delete_envelope),
        )
        // sync
        .route(
            paths::SYNC_PUSH,
            post(s::push).layer(DefaultBodyLimit::max(limits::MAX_PUSH_BODY_BYTES)),
        )
        .route(paths::SYNC_CHANGES, get(s::changes))
        .route(paths::SYNC_SNAPSHOT, get(s::snapshot))
        // events
        .route(paths::EVENTS_WS, get(events::ws::events_ws))
        // vault recovery (account recovery lives in `auth_public`)
        .route(
            paths::RECOVERY_VAULT_ENVELOPE,
            get(recovery::vault_material),
        )
        .route(
            paths::RECOVERY_VAULT_PASSWORD_REPLACE,
            post(recovery::replace_password_envelope),
        )
        .route(
            paths::RECOVERY_VAULT_RECOVERY_REPLACE,
            post(recovery::replace_recovery_envelope),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            auth::middleware::authenticate,
        ));

    let api =
        Router::new()
            .merge(auth_public)
            .merge(authed)
            .route_layer(axum_mw::from_fn_with_state(
                state.clone(),
                middleware::protocol_gate,
            ));

    Router::new()
        .route(paths::META, get(meta::get_meta))
        .route(paths::ops::HEALTHZ, get(meta::healthz))
        .route(paths::ops::READYZ, get(meta::readyz))
        .merge(api)
        .merge(web::router())
        .fallback(middleware::not_found)
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(axum_mw::from_fn(middleware::request_context))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::security_headers,
        ))
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .with_state(state)
}

fn panic_response(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    // Never echo the panic payload (it could contain data).
    tracing::error!("handler panicked");
    let body = cc_protocol::ApiError {
        code: cc_protocol::ErrorCode::Internal,
        message: "internal server error".into(),
        details: None,
        request_id: error::current_request_id(),
        retry_after_seconds: None,
    };
    let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Run the server until SIGINT/SIGTERM.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let pool = db::connect(&config).await?;
    if config.run_migrations {
        db::migrate(&pool).await?;
        tracing::info!("database migrations applied");
    }
    if let Some(addr) = config.metrics_listen {
        let handle = telemetry::install_metrics()?;
        tokio::spawn(telemetry::serve_metrics(addr, handle, pool.clone()));
    }
    if !config.require_request_proof {
        tracing::warn!(
            "CC_REQUIRE_REQUEST_PROOF=false: requests without a device proof are accepted, \
             so a stolen access/refresh token works without the device key. Use only while \
             migrating clients that do not sign yet (watch cc_request_proofs_total{{result=\"missing\"}})."
        );
    }
    let listen_addr = config.listen_addr;
    let state = AppState::new(config, pool).await?;
    jobs::spawn(state.clone());
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = %listener.local_addr()?, version = env!("CARGO_PKG_VERSION"), "consolecrypt-server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    tracing::info!("shut down");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
