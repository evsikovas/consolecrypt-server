// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Application errors, rendered as `cc_protocol::ApiError` JSON bodies.
//!
//! Messages are static, human-readable and never contain request data:
//! no tokens, passwords, envelopes, ciphertext or echoed input.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cc_protocol::{ApiError, ErrorCode, RequestId};
use std::borrow::Cow;

tokio::task_local! {
    /// Request id of the request being served (set by the request-context
    /// middleware) so errors and audit rows can carry it.
    pub static REQUEST_ID: RequestId;
}

/// Request id of the current request, if called inside one.
pub fn current_request_id() -> Option<RequestId> {
    REQUEST_ID.try_with(|id| *id).ok()
}

pub type AppResult<T> = Result<T, AppError>;

#[derive(thiserror::Error)]
pub enum AppError {
    #[error("{code:?}: {message}")]
    Api {
        code: ErrorCode,
        message: Cow<'static, str>,
        details: Option<serde_json::Value>,
        retry_after_seconds: Option<u32>,
    },
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl std::fmt::Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppError")
            .field("code", &self.code())
            .finish_non_exhaustive()
    }
}

/// Safe for logs at every level; never format a database's free-form message.
pub(crate) fn database_error_kind(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Database(_) => "database",
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Protocol(_) => "protocol",
        sqlx::Error::RowNotFound => "row_not_found",
        _ => "database_internal",
    }
}

/// Keep background/startup anyhow contexts from echoing remote error strings.
pub(crate) fn internal_error_kind(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<sqlx::Error>()
        .map(database_error_kind)
        .unwrap_or("internal")
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        AppError::Api {
            code,
            message: message.into(),
            details: None,
            retry_after_seconds: None,
        }
    }

    pub fn with_details(self, value: serde_json::Value) -> Self {
        match self {
            AppError::Api {
                code,
                message,
                retry_after_seconds,
                ..
            } => AppError::Api {
                code,
                message,
                details: Some(value),
                retry_after_seconds,
            },
            other => other,
        }
    }

    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            ErrorCode::Unauthorized,
            "missing, invalid or expired access token",
        )
    }

    pub fn invalid_credentials() -> Self {
        Self::new(ErrorCode::InvalidCredentials, "invalid email or password")
    }

    pub fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }

    pub fn device_revoked() -> Self {
        Self::new(ErrorCode::DeviceRevoked, "this device has been revoked")
    }

    pub fn device_not_trusted() -> Self {
        Self::new(
            ErrorCode::DeviceNotTrusted,
            "this device is not trusted for the vault",
        )
    }

    pub fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, "not found")
    }

    /// `409 already_exists` with `details.field` naming what collided
    /// (`email`, `device_id`, `vault_id`).
    pub fn already_exists(field: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::AlreadyExists, message)
            .with_details(serde_json::json!({ "field": field }))
    }

    pub fn gone(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::Gone, message)
    }

    pub fn payload_too_large(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::PayloadTooLarge, message)
    }

    pub fn invalid_proof(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::InvalidProof, message)
    }

    pub fn rate_limited(retry_after_seconds: u32) -> Self {
        AppError::Api {
            code: ErrorCode::RateLimited,
            message: "too many requests".into(),
            details: None,
            retry_after_seconds: Some(retry_after_seconds.max(1)),
        }
    }

    pub fn internal(message: &'static str) -> Self {
        AppError::Internal(anyhow::anyhow!(message))
    }

    /// The protocol error code this error maps to.
    pub fn code(&self) -> ErrorCode {
        match self {
            AppError::Api { code, .. } => *code,
            AppError::Db(sqlx::Error::PoolTimedOut) => ErrorCode::Unavailable,
            AppError::Db(_) | AppError::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl From<crate::crypto::HasherBusy> for AppError {
    fn from(_: crate::crypto::HasherBusy) -> Self {
        AppError::Api {
            code: ErrorCode::Unavailable,
            message: "server busy, retry later".into(),
            details: None,
            retry_after_seconds: Some(5),
        }
    }
}

impl From<crate::crypto::HashError> for AppError {
    fn from(err: crate::crypto::HashError) -> Self {
        match err {
            crate::crypto::HashError::Busy(b) => b.into(),
            crate::crypto::HashError::Internal(e) => AppError::Internal(e),
        }
    }
}

/// True if `err` is a PostgreSQL unique-constraint violation.
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.code();
        let (message, details, retry_after_seconds): (Cow<'static, str>, _, _) = match self {
            AppError::Api {
                message,
                details,
                retry_after_seconds,
                ..
            } => (message, details, retry_after_seconds),
            AppError::Db(err) => {
                // Server/driver errors are untrusted and can echo input.
                tracing::error!(failure = database_error_kind(&err), "database error");
                if code == ErrorCode::Unavailable {
                    ("service temporarily unavailable".into(), None, Some(5))
                } else {
                    ("internal server error".into(), None, None)
                }
            }
            AppError::Internal(_) => {
                tracing::error!("internal error (details redacted)");
                ("internal server error".into(), None, None)
            }
        };
        let body = ApiError {
            code,
            message: message.into_owned(),
            details,
            request_id: current_request_id(),
            retry_after_seconds,
        };
        let status =
            StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = (status, axum::Json(body)).into_response();
        if let Some(secs) = retry_after_seconds {
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

/// Spawn a background task that keeps the current request id (for audit rows
/// and error bodies) and tracing span.
pub fn spawn_in_request<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    use tracing::Instrument as _;
    let span = tracing::Span::current();
    match current_request_id() {
        Some(id) => {
            tokio::spawn(REQUEST_ID.scope(id, fut).instrument(span));
        }
        None => {
            tokio::spawn(fut.instrument(span));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn database_and_internal_errors_have_redacted_debug_and_display() {
        let secret = uuid::Uuid::new_v4().to_string();
        for error in [
            AppError::Internal(anyhow::anyhow!(secret.clone())),
            AppError::Db(sqlx::Error::Protocol(secret.clone())),
        ] {
            assert!(!format!("{error} {error:?}").contains(&secret));
        }
        assert_eq!(
            database_error_kind(&sqlx::Error::Protocol(secret)),
            "protocol"
        );
    }
}
