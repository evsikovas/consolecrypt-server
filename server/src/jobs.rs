// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Periodic maintenance / retention (SERVER_PLAN S6).
//!
//! Runs on every replica, but each pass takes a PostgreSQL advisory lock so
//! only one replica does the work at a time. Every step is an idempotent,
//! bounded `UPDATE`/`DELETE`; nothing here reads vault content.

use crate::state::AppState;
use serde::Serialize;
use std::time::Duration;

/// Advisory-lock key ("ccmaint" as ASCII) shared by all replicas.
const MAINTENANCE_LOCK_KEY: i64 = 0x63_63_6d_61_69_6e_74;

/// Retention settings (days; 0 disables that step).
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Revoked/expired sessions (and their refresh tokens) kept this long.
    pub session_days: u32,
    /// Idempotency records of accepted mutations. A client retrying a push
    /// older than this is re-evaluated like a new mutation.
    pub sync_mutation_days: u32,
    /// Audit trail.
    pub audit_days: u32,
    /// Deleted vaults (ciphertext, envelopes) are purged after this grace.
    pub deleted_vault_days: u32,
    /// Decided/expired device trust requests.
    pub device_request_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            session_days: 7,
            sync_mutation_days: 30,
            audit_days: 365,
            deleted_vault_days: 30,
            device_request_days: 90,
        }
    }
}

/// What one pass did (row counts), for logs and tests.
#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub skipped_locked: bool,
    pub requests_expired: u64,
    pub requests_deleted: u64,
    pub sessions_deleted: u64,
    pub refresh_tokens_deleted: u64,
    pub account_tokens_deleted: u64,
    pub login_nonces_deleted: u64,
    /// Expired "This wasn't me" tokens, rate counters and issuance markers.
    pub protection_rows_deleted: u64,
    /// Expired OIDC flows / login codes and LDAP failure windows (1.8).
    pub enterprise_rows_deleted: u64,
    /// Request-limit buckets untouched for a day (full again, S2).
    pub rate_buckets_deleted: u64,
    /// Tombstones of all vaults (also exported as `cc_tombstones_total`).
    pub tombstones: i64,
    pub sync_mutations_deleted: u64,
    pub vaults_purged: u64,
    /// Retained content of owner-deleted shared items past the restore window.
    pub shared_restores_expired: u64,
    pub audit_events_deleted: u64,
}

/// Days as the `int4` `make_interval` expects (config validation caps them).
fn days(d: u32) -> i32 {
    i32::try_from(d).unwrap_or(i32::MAX)
}

/// Start the periodic task (no-op when the interval is zero).
pub fn spawn(state: AppState) {
    let interval = state.config.maintenance_interval;
    if interval.is_zero() {
        return;
    }
    tokio::spawn(async move {
        // Small initial delay so startup (migrations, probes) settles.
        tokio::time::sleep(Duration::from_secs(30).min(interval)).await;
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            match run_once(&state).await {
                Ok(report) if !report.skipped_locked => {
                    tracing::info!(report = ?report, "maintenance pass finished")
                }
                Ok(_) => tracing::debug!("maintenance skipped: another replica holds the lock"),
                Err(err) => tracing::warn!(
                    failure = crate::error::internal_error_kind(&err),
                    "maintenance pass failed"
                ),
            }
        }
    });
}

/// One maintenance pass.
pub async fn run_once(state: &AppState) -> anyhow::Result<MaintenanceReport> {
    let r = &state.config.retention;
    let mut report = MaintenanceReport::default();
    // Session-level advisory lock on a dedicated connection.
    let mut conn = state.db.acquire().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(MAINTENANCE_LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        report.skipped_locked = true;
        return Ok(report);
    }
    let result = async {
        report.requests_expired = sqlx::query(
            "UPDATE device_requests SET status = 'expired', decided_at = now()
              WHERE status = 'pending' AND expires_at <= now()",
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();

        if r.device_request_days > 0 {
            report.requests_deleted = sqlx::query(
                "DELETE FROM device_requests
                  WHERE status <> 'pending'
                    AND COALESCE(decided_at, expires_at) < now() - make_interval(days => $1)",
            )
            .bind(days(r.device_request_days))
            .execute(&mut *conn)
            .await?
            .rows_affected();
        }

        // Both login and request proofs retain their nonce beyond their
        // allowed clock-skew window. Only expired markers are safe to remove.
        report.login_nonces_deleted =
            sqlx::query("DELETE FROM device_login_nonces WHERE expires_at < now()")
                .execute(&mut *conn)
                .await?
                .rows_affected();

        // Refresh tokens past expiry can no longer be replayed meaningfully.
        report.refresh_tokens_deleted =
            sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now()")
                .execute(&mut *conn)
                .await?
                .rows_affected();
        if r.session_days > 0 {
            report.sessions_deleted = sqlx::query(
                "DELETE FROM sessions
                  WHERE COALESCE(revoked_at, expires_at) < now() - make_interval(days => $1)
                    AND (revoked_at IS NOT NULL OR expires_at < now())",
            )
            .bind(days(r.session_days))
            .execute(&mut *conn)
            .await?
            .rows_affected();
        }
        report.account_tokens_deleted =
            sqlx::query("DELETE FROM account_tokens WHERE expires_at < now() - interval '1 day'")
                .execute(&mut *conn)
                .await?
                .rows_affected();

        // Device protection: windows are at most a day long; deny tokens
        // live 7 days and are kept one more day for support questions.
        for sql in [
            "DELETE FROM device_deny_tokens WHERE expires_at < now() - interval '1 day'",
            "DELETE FROM rate_counters WHERE window_start < now() - interval '2 days'",
            "DELETE FROM envelope_issuances WHERE window_start < now() - interval '2 days'",
        ] {
            report.protection_rows_deleted +=
                sqlx::query(sql).execute(&mut *conn).await?.rows_affected();
        }

        // A bucket untouched for a day has refilled completely (no default
        // limit takes longer), so dropping it changes nothing.
        report.rate_buckets_deleted =
            sqlx::query("DELETE FROM rate_buckets WHERE updated_at < now() - interval '1 day'")
                .execute(&mut *conn)
                .await?
                .rows_affected();
        report.tombstones = sqlx::query_scalar(
            "SELECT COALESCE(sum(tombstone_count), 0)::bigint FROM vault_sequences",
        )
        .fetch_one(&mut *conn)
        .await?;
        metrics::gauge!("cc_tombstones_total").set(report.tombstones as f64);

        // Enterprise sign-in: flows live 10 min, login codes 60 s, failure
        // windows at most a day.
        for sql in [
            "DELETE FROM oidc_flows WHERE expires_at < now()",
            "DELETE FROM oidc_login_codes WHERE expires_at < now() - interval '1 hour'",
            "DELETE FROM ldap_login_failures WHERE window_start < now() - interval '2 days'",
        ] {
            report.enterprise_rows_deleted +=
                sqlx::query(sql).execute(&mut *conn).await?.rows_affected();
        }

        if r.sync_mutation_days > 0 {
            report.sync_mutations_deleted = sqlx::query(
                "DELETE FROM sync_mutations WHERE accepted_at < now() - make_interval(days => $1)",
            )
            .bind(days(r.sync_mutation_days))
            .execute(&mut *conn)
            .await?
            .rows_affected();
        }
        if r.deleted_vault_days > 0 {
            // Cascades to members, sequences, envelopes, objects, mutations.
            report.vaults_purged = sqlx::query(
                "DELETE FROM vaults
                  WHERE state = 'deleted' AND deleted_at < now() - make_interval(days => $1)",
            )
            .bind(days(r.deleted_vault_days))
            .execute(&mut *conn)
            .await?
            .rows_affected();
        }
        // The signed tombstone stays; only the restorable ciphertext goes.
        report.shared_restores_expired = sqlx::query(
            "UPDATE shared_items SET restore_revision = NULL
              WHERE restore_revision IS NOT NULL
                AND deleted_at < now() - make_interval(days => $1)",
        )
        .bind(days(cc_protocol::sharing::RESTORE_WINDOW_DAYS))
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if r.audit_days > 0 {
            report.audit_events_deleted = sqlx::query(
                "DELETE FROM audit_events WHERE occurred_at < now() - make_interval(days => $1)",
            )
            .bind(days(r.audit_days))
            .execute(&mut *conn)
            .await?
            .rows_affected();
        }
        anyhow::Ok(())
    }
    .await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MAINTENANCE_LOCK_KEY)
        .execute(&mut *conn)
        .await;
    result?;
    Ok(report)
}
