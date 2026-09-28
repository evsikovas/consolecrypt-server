// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Authentication middleware for every authenticated route: bearer token →
//! principal A, then the per-request device proof (protocol 1.5).
//!
//! The body is buffered and hashed only *after* the token authenticated, so
//! an anonymous client can never make the server buffer a large body.

use super::context::lookup;
use crate::crypto;
use crate::error::AppError;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cc_protocol::devices::RequestProof;
use cc_protocol::version::HEADER_DEVICE_PROOF;
use cc_protocol::{canonical, limits, paths, DeviceId};
use chrono::Utc;
use sqlx::PgExecutor;
use uuid::Uuid;

pub async fn authenticate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let (ctx, signing_key) = match lookup(&state, &parts).await {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    let body = match parts.headers.get(HEADER_DEVICE_PROOF) {
        None => {
            metrics::counter!("cc_request_proofs_total", "result" => "missing").increment(1);
            if state.config.require_request_proof {
                return proof_error("missing").into_response();
            }
            body
        }
        Some(value) => {
            let Some(proof) = value.to_str().ok().and_then(RequestProof::decode) else {
                return proof_error("malformed").into_response();
            };
            let limit = if parts.uri.path() == paths::SYNC_PUSH {
                limits::MAX_PUSH_BODY_BYTES
            } else {
                crate::DEFAULT_BODY_LIMIT
            };
            let bytes = match axum::body::to_bytes(body, limit).await {
                Ok(b) => b,
                Err(_) => {
                    return AppError::payload_too_large("request body too large").into_response()
                }
            };
            let body_hash = crypto::sha256(&bytes);
            if let Err(err) = verify_request_proof(
                &state.db,
                ctx.device_id,
                &signing_key,
                &parts,
                &body_hash,
                &proof,
            )
            .await
            {
                return err.into_response();
            }
            Body::from(bytes)
        }
    };
    parts.extensions.insert(ctx);
    next.run(Request::from_parts(parts, body)).await
}

pub(crate) fn proof_error(reason: &'static str) -> AppError {
    metrics::counter!("cc_request_proofs_total", "result" => reason).increment(1);
    AppError::invalid_proof("request proof missing or invalid")
        .with_details(serde_json::json!({ "reason": reason }))
}

/// Request-target as sent (`path?query`).
pub(crate) fn path_and_query(parts: &Parts) -> &str {
    parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |pq| pq.as_str())
}

/// Verify a per-request proof against `signing_key` and consume its nonce.
pub(crate) async fn verify_request_proof<'e>(
    db: impl PgExecutor<'e>,
    device_id: DeviceId,
    signing_key: &[u8],
    parts: &Parts,
    body_hash: &[u8; 32],
    proof: &RequestProof,
) -> Result<(), AppError> {
    let now = Utc::now().timestamp();
    if (now - proof.issued_at).abs() > limits::MAX_REQUEST_PROOF_SKEW_SECONDS {
        return Err(proof_error("stale"));
    }
    let message = canonical::request_proof_message(
        device_id,
        parts.method.as_str(),
        path_and_query(parts),
        body_hash,
        proof.issued_at,
        &proof.nonce,
    );
    if !crypto::verify_ed25519(signing_key, &message, &proof.signature) {
        return Err(proof_error("invalid_signature"));
    }
    // Same single-use table as login proofs (labels differ, so the two
    // kinds can never be confused; sharing only means a nonce is used once).
    let expires_at = proof.issued_at.max(now) + limits::MAX_REQUEST_PROOF_SKEW_SECONDS + 60;
    let inserted = sqlx::query(
        "INSERT INTO device_login_nonces (device_id, nonce, expires_at)
         VALUES ($1, $2, to_timestamp($3))
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from(device_id))
    .bind(&proof.nonce[..])
    .bind(expires_at as f64)
    .execute(db)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(proof_error("replayed"));
    }
    metrics::counter!("cc_request_proofs_total", "result" => "valid").increment(1);
    Ok(())
}
