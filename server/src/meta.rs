// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `GET /v1/meta` and operational probes.

use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use cc_protocol::meta::{AuthCapability, AuthMode, AuthProvider, ServerCapabilities, ServerInfo};
use cc_protocol::version::HEADER_PROTOCOL_VERSION;
use cc_protocol::{ProtocolVersion, PROTOCOL_VERSION};

/// Oldest client protocol this server accepts.
pub const MINIMUM_SUPPORTED_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 0);

pub fn server_info(state: &AppState, upgrade_required: bool) -> ServerInfo {
    // Same gate as `sharing::require_enabled`.
    let sharing = state.config.object_sharing_enabled && state.config.require_request_proof;
    ServerInfo {
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        minimum_supported_protocol: MINIMUM_SUPPORTED_PROTOCOL,
        upgrade_required,
        // Enterprise accounts are created by the first IdP/directory sign-in.
        registration_open: state.config.registration_open && !state.config.auth.is_enterprise(),
        email_verification_required: state.config.require_email_verification,
        source_code_url: Some(state.config.source_code_url.clone()),
        capabilities: ServerCapabilities {
            device_protection: state.config.device_protection.enabled,
            share_leave: sharing,
            share_restore: sharing,
            recipient_lookup_post: sharing,
            auth: auth_capability(&state.config.auth),
            teams: state.config.teams_enabled,
            vrk_commitment: true,
            team_key_commitment: true,
        },
    }
}

/// `capabilities.auth` (protocol 1.9).
pub fn auth_capability(auth: &crate::config::AuthConfig) -> AuthCapability {
    match auth.enterprise_provider() {
        None => AuthCapability::default(),
        Some(p) => AuthCapability {
            mode: AuthMode::Enterprise,
            provider: Some(match p {
                crate::config::ProviderKind::Oidc => AuthProvider::Oidc,
                crate::config::ProviderKind::Ldap => AuthProvider::Ldap,
            }),
            display_name: auth.display_name.clone(),
        },
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
