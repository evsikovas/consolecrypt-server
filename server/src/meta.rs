// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `GET /v1/meta` and operational probes.

use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use cc_protocol::meta::ServerInfo;
use cc_protocol::version::HEADER_PROTOCOL_VERSION;
use cc_protocol::{ProtocolVersion, PROTOCOL_VERSION};

/// Oldest client protocol this server accepts.
pub const MINIMUM_SUPPORTED_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 0);

pub fn server_info(state: &AppState, upgrade_required: bool) -> ServerInfo {
    ServerInfo {
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        minimum_supported_protocol: MINIMUM_SUPPORTED_PROTOCOL,
        upgrade_required,
        registration_open: state.config.registration_open,
        email_verification_required: state.config.require_email_verification,
        source_code_url: Some(state.config.source_code_url.clone()),
    }
}

/// Always answers (never 426) so an outdated client can learn it must upgrade.
pub async fn get_meta(State(state): State<AppState>, headers: HeaderMap) -> Json<ServerInfo> {
    let upgrade_required = headers
        .get(HEADER_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<ProtocolVersion>().ok())
        .is_some_and(|v| !PROTOCOL_VERSION.is_compatible(&v, &MINIMUM_SUPPORTED_PROTOCOL));
    Json(server_info(&state, upgrade_required))
}

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "ready"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable"),
    }
}
