// SPDX-License-Identifier: AGPL-3.0-only
//! Experimental per-object sharing. Personal vault rights are never consulted.
mod auth;
mod enrollment;
mod enrollment_handlers;
mod enrollment_store;
pub mod handlers;
pub mod service;
mod store;

use crate::{
    error::{AppError, AppResult},
    AppState,
};
use uuid::Uuid;

pub(super) fn require_enabled(state: &AppState) -> AppResult<()> {
    if !state.config.object_sharing_enabled || !state.config.require_request_proof {
        return Err(AppError::not_found());
    }
    Ok(())
}

/// Stable public identifier, persisted independently of deployment URL.
pub async fn instance_id(state: &AppState) -> AppResult<Uuid> {
    require_enabled(state)?;
    Ok(
        sqlx::query_scalar("SELECT instance_id FROM sharing_instance WHERE singleton")
            .fetch_one(&state.db)
            .await?,
    )
}
