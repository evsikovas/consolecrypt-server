// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Storage of VRK key envelopes. Envelopes are opaque ciphertext to the
//! server: it validates structure (lengths, algorithm/recipient consistency,
//! KDF floor) and stores them, nothing more.

use crate::error::{AppError, AppResult};
use crate::util::{enum_str, parse_enum};
use cc_protocol::envelopes::{EnvelopeMetadata, KeyEnvelope, NewEnvelope, RecipientType};
use cc_protocol::{DeviceId, EnvelopeId, VaultId};
use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// Structural validation (`NewEnvelope::validate`) plus an expected
/// recipient type.
pub fn validate(env: &NewEnvelope, expected: RecipientType) -> AppResult<()> {
    if env.recipient_type != expected {
        return Err(AppError::bad_request(format!(
            "expected a {} envelope",
            enum_str(&expected)
        )));
    }
    env.validate()
        .map_err(|e| AppError::bad_request(format!("invalid envelope: {e}")))
}

#[derive(sqlx::FromRow)]
pub(crate) struct EnvelopeRow {
    id: Uuid,
    vault_id: Uuid,
    recipient_type: String,
    recipient_id: Option<Uuid>,
    kind: String,
    metadata: Json<EnvelopeMetadata>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    created_at: DateTime<Utc>,
    created_by_device_id: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
}

pub(crate) const ENVELOPE_COLUMNS: &str = "id, vault_id, recipient_type, recipient_id, kind, \
     metadata, ciphertext, nonce, created_at, created_by_device_id, revoked_at";

impl EnvelopeRow {
    pub(crate) fn into_dto(self) -> AppResult<KeyEnvelope> {
        Ok(KeyEnvelope {
            envelope_id: self.id.into(),
            vault_id: self.vault_id.into(),
            recipient_type: parse_enum(&self.recipient_type)?,
            recipient_id: self.recipient_id,
            kind: parse_enum(&self.kind)?,
            metadata: self.metadata.0,
            ciphertext: self.ciphertext.into(),
            nonce: self.nonce.into(),
            created_at: self.created_at,
            created_by_device_id: self.created_by_device_id.map(DeviceId::from),
            revoked_at: self.revoked_at,
        })
    }
}

/// Insert `env` for `vault_id`, atomically revoking the live envelope of the
/// same recipient (if any). Callers run this inside a transaction.
pub async fn store(
    conn: &mut PgConnection,
    vault_id: VaultId,
    env: &NewEnvelope,
    created_by: DeviceId,
    replaced_reason: &str,
) -> AppResult<KeyEnvelope> {
    sqlx::query(
        "UPDATE vault_key_envelopes SET revoked_at = now(), revoke_reason = $4
          WHERE vault_id = $1 AND recipient_type = $2
            AND recipient_id IS NOT DISTINCT FROM $3 AND revoked_at IS NULL",
    )
    .bind(Uuid::from(vault_id))
    .bind(enum_str(&env.recipient_type))
    .bind(env.recipient_id)
    .bind(replaced_reason)
    .execute(&mut *conn)
    .await?;

    let row: EnvelopeRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO vault_key_envelopes
             (id, vault_id, recipient_type, recipient_id, kind, algorithm, metadata,
              ciphertext, nonce, created_by_device_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING {ENVELOPE_COLUMNS}"
    )))
    .bind(Uuid::from(EnvelopeId::new()))
    .bind(Uuid::from(vault_id))
    .bind(enum_str(&env.recipient_type))
    .bind(env.recipient_id)
    .bind(enum_str(&env.kind))
    .bind(enum_str(&env.metadata.algorithm))
    .bind(Json(&env.metadata))
    .bind(env.ciphertext.as_slice())
    .bind(env.nonce.as_slice())
    .bind(Uuid::from(created_by))
    .fetch_one(conn)
    .await?;
    row.into_dto()
}

/// Which live envelopes of a vault a caller may see (ADR-0004).
#[derive(Debug, Clone, Copy)]
pub enum Visibility {
    /// Trusted device: every live envelope.
    All,
    /// Untrusted member device: password + recovery + its own device envelope.
    UnlockMaterial { device_id: DeviceId },
}

pub async fn list_live<'e>(
    db: impl PgExecutor<'e>,
    vault_id: VaultId,
    visibility: Visibility,
) -> AppResult<Vec<KeyEnvelope>> {
    let own_device: Option<Uuid> = match visibility {
        Visibility::All => None,
        Visibility::UnlockMaterial { device_id } => Some(device_id.into()),
    };
    let rows: Vec<EnvelopeRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {ENVELOPE_COLUMNS} FROM vault_key_envelopes
          WHERE vault_id = $1 AND revoked_at IS NULL
            AND ($2 OR recipient_type IN ('password', 'recovery')
                 OR (recipient_type = 'device' AND recipient_id = $3))
          ORDER BY created_at, id"
    )))
    .bind(Uuid::from(vault_id))
    .bind(matches!(visibility, Visibility::All))
    .bind(own_device)
    .fetch_all(db)
    .await?;
    rows.into_iter().map(EnvelopeRow::into_dto).collect()
}

/// The live envelope of one recipient, if any.
pub async fn live_for<'e>(
    db: impl PgExecutor<'e>,
    vault_id: VaultId,
    recipient_type: RecipientType,
    recipient_id: Option<Uuid>,
) -> AppResult<Option<KeyEnvelope>> {
    let row: Option<EnvelopeRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {ENVELOPE_COLUMNS} FROM vault_key_envelopes
          WHERE vault_id = $1 AND recipient_type = $2
            AND recipient_id IS NOT DISTINCT FROM $3 AND revoked_at IS NULL"
    )))
    .bind(Uuid::from(vault_id))
    .bind(enum_str(&recipient_type))
    .bind(recipient_id)
    .fetch_optional(db)
    .await?;
    row.map(EnvelopeRow::into_dto).transpose()
}
