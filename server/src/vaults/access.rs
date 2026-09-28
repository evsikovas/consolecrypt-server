// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Vault authorization predicates of ADR-0004: membership, **T(V)** (trusted
//! device) and **K(V)** (vault access key).

use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::parse_enum;
use cc_protocol::vaults::{VaultInfo, VaultRole, VaultState};
use cc_protocol::{Bytes, UserId, VaultId};
use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use std::net::IpAddr;
use uuid::Uuid;

/// The caller's view of a vault.
#[derive(Debug, Clone)]
pub struct VaultAccess {
    pub vault_id: VaultId,
    pub owner_user_id: UserId,
    pub role: VaultRole,
    pub state: VaultState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deletion_scheduled_at: Option<DateTime<Utc>>,
    pub latest_sequence: i64,
    /// T(V): the calling device holds a live device envelope for the vault.
    pub trusted: bool,
    /// Vault epoch (protocol 1.3), rotated after a server restore.
    pub epoch: Uuid,
    access_key_verifier: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct AccessRow {
    owner_user_id: Uuid,
    state: String,
    access_key_verifier: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deletion_scheduled_at: Option<DateTime<Utc>>,
    role: String,
    last_sequence: i64,
    trusted: bool,
    epoch: Uuid,
}

impl VaultAccess {
    /// Load the vault as seen by `auth`. Not a member (or no such vault) →
    /// `404`; deleted → `410`.
    pub async fn load<'e>(
        db: impl PgExecutor<'e>,
        auth: &AuthContext,
        vault_id: VaultId,
    ) -> AppResult<Self> {
        let row: Option<AccessRow> = sqlx::query_as(
            "SELECT v.owner_user_id, v.state, v.access_key_verifier, v.created_at, v.updated_at,
                    v.deletion_scheduled_at, v.epoch, m.role, s.last_sequence,
                    EXISTS (SELECT 1 FROM vault_key_envelopes e
                             WHERE e.vault_id = v.id AND e.recipient_type = 'device'
                               AND e.recipient_id = $3 AND e.revoked_at IS NULL) AS trusted
               FROM vaults v
               JOIN vault_members m ON m.vault_id = v.id AND m.user_id = $2 AND m.revoked_at IS NULL
               JOIN vault_sequences s ON s.vault_id = v.id
              WHERE v.id = $1",
        )
        .bind(Uuid::from(vault_id))
        .bind(Uuid::from(auth.user_id))
        .bind(Uuid::from(auth.device_id))
        .fetch_optional(db)
        .await?;
        let row = row.ok_or_else(AppError::not_found)?;
        let state: VaultState = parse_enum(&row.state)?;
        if state == VaultState::Deleted {
            return Err(AppError::gone("vault was deleted"));
        }
        Ok(Self {
            vault_id,
            owner_user_id: row.owner_user_id.into(),
            role: parse_enum(&row.role)?,
            state,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deletion_scheduled_at: row.deletion_scheduled_at,
            latest_sequence: row.last_sequence,
            trusted: row.trusted,
            epoch: row.epoch,
            access_key_verifier: row.access_key_verifier,
        })
    }

    /// Require T(V).
    pub fn require_trusted(&self) -> AppResult<&Self> {
        if self.trusted {
            Ok(self)
        } else {
            Err(AppError::device_not_trusted())
        }
    }

    /// Constant-time K(V) check.
    pub fn key_matches(&self, vault_access_key: &Bytes) -> bool {
        crypto::verify_vault_access_key(vault_access_key.as_slice(), &self.access_key_verifier)
    }

    pub fn info(&self) -> VaultInfo {
        VaultInfo {
            vault_id: self.vault_id,
            owner_user_id: self.owner_user_id,
            role: self.role,
            state: self.state,
            created_at: self.created_at,
            updated_at: self.updated_at,
            latest_sequence: self.latest_sequence,
            caller_trusted: self.trusted,
            deletion_scheduled_at: self.deletion_scheduled_at,
            epoch: Some(self.epoch),
        }
    }
}

/// Rate-limit and verify K(V); failures are audited as `failure`.
pub async fn require_access_key(
    state: &AppState,
    auth: &AuthContext,
    ip: Option<IpAddr>,
    access: &VaultAccess,
    vault_access_key: &Bytes,
    failure: AuditType,
) -> AppResult<()> {
    state
        .limits
        .proof_device
        .check(&Uuid::from(auth.device_id))?;
    if access.key_matches(vault_access_key) {
        return Ok(());
    }
    metrics::counter!("cc_vault_proof_failures_total").increment(1);
    AuditEvent::new(failure)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(access.vault_id)
        .ip(ip)
        .record(&state.db)
        .await?;
    Err(AppError::invalid_proof("invalid vault access key"))
}

/// T(V) + K(V) in one step.
pub async fn require_trusted_with_key(
    state: &AppState,
    auth: &AuthContext,
    ip: Option<IpAddr>,
    vault_id: VaultId,
    vault_access_key: &Bytes,
) -> AppResult<VaultAccess> {
    let access = VaultAccess::load(&state.db, auth, vault_id).await?;
    access.require_trusted()?;
    require_access_key(
        state,
        auth,
        ip,
        &access,
        vault_access_key,
        AuditType::VaultProofFailed,
    )
    .await?;
    Ok(access)
}
