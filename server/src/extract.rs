// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Extractors with sanitised rejections.
//!
//! Axum's default JSON/query rejections include serde error text, which can
//! echo parts of the input (e.g. a password sent with the wrong type). These
//! wrappers replace them with generic `ApiError`s that carry no input data.

use crate::error::AppError;
use crate::state::AppState;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use serde::de::DeserializeOwned;
use std::net::{IpAddr, SocketAddr};

fn short_type_name<T>() -> &'static str {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full)
}

/// JSON body extractor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(rejection) => Err(json_rejection::<T>(&rejection)),
        }
    }
}

fn json_rejection<T>(rejection: &JsonRejection) -> AppError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return AppError::payload_too_large("request body too large");
    }
    match rejection {
        JsonRejection::JsonDataError(_) => AppError::bad_request(format!(
            "request body does not match {}",
            short_type_name::<T>()
        )),
        JsonRejection::JsonSyntaxError(_) => AppError::bad_request("malformed JSON body"),
        JsonRejection::MissingJsonContentType(_) => {
            AppError::bad_request("expected Content-Type: application/json")
        }
        _ => AppError::bad_request("could not read request body"),
    }
}

/// Query-string extractor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(v)) => Ok(ApiQuery(v)),
            Err(QueryRejection::FailedToDeserializeQueryString(_)) | Err(_) => Err(
                AppError::bad_request(format!("invalid query for {}", short_type_name::<T>())),
            ),
        }
    }
}

/// Path-parameter extractor (malformed ids → 400).
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiPath<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(v)) => Ok(ApiPath(v)),
            Err(PathRejection::FailedToDeserializePathParams(_)) | Err(_) => {
                Err(AppError::bad_request("invalid path parameter"))
            }
        }
    }
}

/// Best-effort client IP for rate limiting and audit.
///
/// Uses the TCP peer address, or — when `CC_TRUST_PROXY_HEADERS=true`, i.e.
/// exactly one trusted reverse proxy sits in front — the right-most
/// `X-Forwarded-For` entry (the address that proxy saw), or the peer if that
/// entry is not an IP address.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        if state.config.trust_proxy_headers {
            // Only the right-most entry was appended by our proxy; anything to
            // its left is client-controlled. If it does not parse, fall back
            // to the peer rather than trusting an earlier entry.
            let last = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .next_back()
                .map(str::trim);
            if let Some(entry) = last {
                return Ok(ClientIp(entry.parse::<IpAddr>().ok().or(peer)));
            }
        }
        Ok(ClientIp(peer))
    }
}

/// JSON body that may be absent (empty body → `T::default()`), for endpoints
/// whose request DTO is optional (logout, revoke, delete vault, trust request).
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJsonOrDefault<T>(pub T);

impl<T, S> FromRequest<S> for ApiJsonOrDefault<T>
where
    T: DeserializeOwned + Default,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|rejection| {
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    AppError::payload_too_large("request body too large")
                } else {
                    AppError::bad_request("could not read request body")
                }
            })?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(ApiJsonOrDefault(T::default()));
        }
        serde_json::from_slice(&bytes)
            .map(ApiJsonOrDefault)
            .map_err(|_| {
                AppError::bad_request(format!(
                    "request body does not match {}",
                    short_type_name::<T>()
                ))
            })
    }
}
