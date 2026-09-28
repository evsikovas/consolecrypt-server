// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Cross-cutting HTTP middleware.
//!
//! Logging here records only method, route template, status, latency and ids.
//! Headers (Authorization!), query strings and bodies are never logged.

use crate::error::{AppError, REQUEST_ID};
use crate::meta;
use crate::state::AppState;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cc_protocol::version::{HEADER_PROTOCOL_VERSION, HEADER_REQUEST_ID};
use cc_protocol::{ErrorCode, ProtocolVersion, RequestId, PROTOCOL_VERSION};
use std::time::Instant;
use tracing::Instrument as _;

/// Request id + tracing span + access log + HTTP metrics.
pub async fn request_context(mut req: Request, next: Next) -> Response {
    // Accept a client-supplied id only if it is a UUID (no log injection).
    let request_id = req
        .headers()
        .get(HEADER_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<RequestId>().ok())
        .unwrap_or_default();
    req.extensions_mut().insert(request_id);

    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let method = req.method().clone();

    let span = tracing::info_span!(
        "http",
        request_id = %request_id,
        method = method_label(&method),
        route = %route,
        user_id = tracing::field::Empty,
        device_id = tracing::field::Empty,
    );
    let started = Instant::now();
    let mut resp = REQUEST_ID
        .scope(request_id, next.run(req))
        .instrument(span.clone())
        .await;
    let elapsed = started.elapsed();
    let status = resp.status().as_u16();

    let latency_ms = elapsed.as_millis() as u64;
    let is_probe = route == "/healthz" || route == "/readyz";
    span.in_scope(|| {
        if is_probe {
            tracing::debug!(status, latency_ms, "request");
        } else {
            tracing::info!(status, latency_ms, "request");
        }
    });
    let labels = [
        ("method", method_label(&method).to_owned()),
        ("route", route),
        ("status", status.to_string()),
    ];
    metrics::counter!("cc_http_requests_total", &labels).increment(1);
    metrics::histogram!("cc_http_request_duration_seconds", &labels[..2])
        .record(elapsed.as_secs_f64());

    if let Ok(v) = HeaderValue::from_str(&request_id.to_string()) {
        resp.headers_mut().insert(HEADER_REQUEST_ID, v);
    }
    resp
}

/// Bounded label set: hyper accepts arbitrary extension methods, which must
/// not create unbounded metric series.
fn method_label(method: &axum::http::Method) -> &'static str {
    use axum::http::Method;
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PATCH => "PATCH",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

/// Protocol-version gate (SERVER_SPEC §24): an incompatible
/// `x-cc-protocol-version` gets `426 upgrade_required` with `ServerInfo`.
/// Requests without the header (curl, probes) pass.
pub async fn protocol_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(value) = req.headers().get(HEADER_PROTOCOL_VERSION) {
        let parsed = value
            .to_str()
            .ok()
            .and_then(|s| s.parse::<ProtocolVersion>().ok());
        match parsed {
            None => {
                return AppError::bad_request("invalid x-cc-protocol-version header")
                    .into_response()
            }
            Some(v) if !PROTOCOL_VERSION.is_compatible(&v, &meta::MINIMUM_SUPPORTED_PROTOCOL) => {
                let info = meta::server_info(&state, true);
                return AppError::new(ErrorCode::UpgradeRequired, "client protocol not supported")
                    .with_details(serde_json::to_value(info).unwrap_or_default())
                    .into_response();
            }
            Some(_) => {}
        }
    }
    next.run(req).await
}

/// Security headers on every response (SERVER_SPEC §18). HSTS is harmless
/// over plain HTTP (browsers ignore it) and useful behind TLS termination.
pub async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let mut set = |name: HeaderName, value: &'static str| {
        h.entry(name).or_insert(HeaderValue::from_static(value));
    };
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "no-referrer");
    set(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'",
    );
    set(header::CACHE_CONTROL, "no-store");
    if state.config.hsts {
        set(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=63072000; includeSubDomains",
        );
    }
    resp
}

/// Fallback for unknown routes: uniform `404` body.
pub async fn not_found() -> Response {
    AppError::not_found().into_response()
}
