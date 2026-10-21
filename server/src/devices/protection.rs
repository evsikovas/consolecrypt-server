// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! New-device protection (security audit 2026-10-21, finding S1; protocol
//! 1.7). Everything here is inert while `CC_DEVICE_PROTECTION_ENABLED=false`,
//! except bookkeeping (`devices.first_trusted_at`, early quarantine lifts)
//! that keeps the data correct for when it is turned on.
//!
//! * **Quarantine**: a device younger than `CC_DEVICE_QUARANTINE_DAYS` may
//!   revoke only itself and untrusted devices, `logout all` signs out only
//!   untrusted devices, and its password change keeps trusted devices signed
//!   in. Unlocking a vault does not end it; approval by a trusted device that
//!   is itself past quarantine does. The recovery kit does not lift it yet
//!   (open question 6.1 of the spec: safe default until the owner decides).
//! * **Envelope metering**: unlock material (password/recovery envelopes)
//!   handed to devices that are not trusted for the vault is limited per
//!   account and per device in fixed PostgreSQL windows, so every replica
//!   enforces the same limit.
//! * **Deny tokens**: single-use "This wasn't me" links in security mails.

use crate::audit::{AuditEvent, AuditType};
use crate::auth::AuthContext;
use crate::config::DeviceProtectionConfig;
use crate::crypto::{self, IssuedToken, TokenKind};
use crate::error::{AppError, AppResult};
use crate::mail::{self, templates};
use crate::state::AppState;
use cc_protocol::devices::DeviceRegistration;
use cc_protocol::events::ServerEvent;
use cc_protocol::{DeviceId, UserId, VaultId};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgExecutor};
use std::net::IpAddr;
use uuid::Uuid;

/// Lifetime of a "This wasn't me" token.
pub const DENY_TOKEN_TTL_DAYS: i64 = 7;

/// SQL predicate: the device in column `col` holds a live device envelope of
/// a vault that is not deleted (T for at least one vault, ADR-0004).
pub(crate) fn trusted_sql(col: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM vault_key_envelopes te
                   JOIN vaults tv ON tv.id = te.vault_id AND tv.state <> 'deleted'
                  WHERE te.recipient_type = 'device' AND te.recipient_id = {col}
                    AND te.revoked_at IS NULL)"
    )
}

/// End of the quarantine of a device, if it is still running.
pub fn quarantine_end(
    prot: &DeviceProtectionConfig,
    created_at: DateTime<Utc>,
    lifted_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    if !prot.enabled || lifted_at.is_some() || revoked_at.is_some() {
        return None;
    }
    let end = created_at + prot.quarantine_span();
    (end > Utc::now()).then_some(end)
}

#[derive(sqlx::FromRow)]
struct QuarantineRow {
    created_at: DateTime<Utc>,
    quarantine_lifted_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Quarantine end of `device_id` (None when not in quarantine).
pub async fn quarantine_of<'e>(
    db: impl PgExecutor<'e>,
    prot: &DeviceProtectionConfig,
    device_id: DeviceId,
) -> AppResult<Option<DateTime<Utc>>> {
    if !prot.enabled {
        return Ok(None);
    }
    let row: Option<QuarantineRow> = sqlx::query_as(
        "SELECT created_at, quarantine_lifted_at, revoked_at FROM devices WHERE id = $1",
    )
    .bind(Uuid::from(device_id))
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|r| quarantine_end(prot, r.created_at, r.quarantine_lifted_at, r.revoked_at)))
}

/// Whether `device_id` is trusted for at least one vault.
pub async fn is_trusted<'e>(db: impl PgExecutor<'e>, device_id: DeviceId) -> AppResult<bool> {
    Ok(
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT {}", trusted_sql("$1"))))
            .bind(Uuid::from(device_id))
            .fetch_one(db)
            .await?,
    )
}

/// Record the first time a device became trusted (any device envelope).
pub async fn mark_trusted(conn: &mut PgConnection, device_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "UPDATE devices SET first_trusted_at = now() WHERE id = $1 AND first_trusted_at IS NULL",
    )
    .bind(device_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Issue a "This wasn't me" token for `device_id`, or (None) for the
/// never-trusted devices that sign in after a password reset.
pub async fn issue_deny_token(
    conn: &mut PgConnection,
    user_id: UserId,
    device_id: Option<DeviceId>,
) -> AppResult<IssuedToken> {
    let token = crypto::issue_token(TokenKind::DenyDevice);
    sqlx::query(
        "INSERT INTO device_deny_tokens (token_hash, user_id, device_id, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(days => $4))",
    )
    .bind(&token.hash[..])
    .bind(Uuid::from(user_id))
    .bind(device_id.map(Uuid::from))
    .bind(DENY_TOKEN_TTL_DAYS as i32)
    .execute(conn)
    .await?;
    Ok(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Hour,
    Day,
}

impl Window {
    const fn unit(self) -> &'static str {
        match self {
            Window::Hour => "hour",
            Window::Day => "day",
        }
    }
}

/// Add one to the counter `(scope, key)` of the current UTC `window`.
/// Returns the new count and the seconds until the window ends. The upsert
/// row-locks the counter, so concurrent callers on any replica serialise.
pub async fn bump(
    conn: &mut PgConnection,
    scope: &str,
    key: Uuid,
    window: Window,
) -> AppResult<(i64, u32)> {
    let (count, left): (i32, f64) = sqlx::query_as(
        "INSERT INTO rate_counters AS c (scope, key, window_start, count)
         VALUES ($1, $2, date_trunc($3, now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', 1)
         ON CONFLICT (scope, key, window_start) DO UPDATE SET count = c.count + 1
         RETURNING c.count,
                   EXTRACT(EPOCH FROM (c.window_start + make_interval(
                       hours => CASE WHEN $3 = 'hour' THEN 1 ELSE 24 END) - now()))::float8",
    )
    .bind(scope)
    .bind(key)
    .bind(window.unit())
    .fetch_one(conn)
    .await?;
    Ok((i64::from(count), left.ceil().clamp(1.0, 86_400.0) as u32))
}

/// TR-9/TR-10: meter unlock material (password/recovery envelopes) handed to
/// a device that is not trusted for `vault_id`. Handing the same vault's
/// material to the same device again within the hour reveals nothing new and
/// is free (0.8.x clients poll it every 5 s while waiting for approval).
pub async fn meter_unlock_material(
    state: &AppState,
    auth: &AuthContext,
    ip: Option<IpAddr>,
    vault_id: VaultId,
    endpoint: &'static str,
) -> AppResult<()> {
    let prot = &state.config.device_protection;
    if !prot.enabled {
        return Ok(());
    }
    let user = Uuid::from(auth.user_id);
    let device = Uuid::from(auth.device_id);
    let mut tx = state.db.begin().await?;
    let fresh = sqlx::query(
        "INSERT INTO envelope_issuances (device_id, vault_id, window_start)
         VALUES ($1, $2, date_trunc('hour', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
         ON CONFLICT DO NOTHING",
    )
    .bind(device)
    .bind(Uuid::from(vault_id))
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if !fresh {
        return Ok(());
    }
    // Always the same order (account hour, account day, device hour): no
    // deadlocks between concurrent hand-outs of one account.
    let limits = [
        (
            "envelopes_account",
            user,
            Window::Hour,
            prot.envelopes_per_account_per_hour,
        ),
        (
            "envelopes_account",
            user,
            Window::Day,
            prot.envelopes_per_account_per_day,
        ),
        (
            "envelopes_device",
            device,
            Window::Hour,
            prot.envelopes_per_device_per_hour,
        ),
    ];
    let mut exceeded: Option<(u32, &'static str)> = None;
    for (scope, key, window, limit) in limits {
        if limit == 0 {
            continue;
        }
        let (count, left) = bump(&mut tx, scope, key, window).await?;
        if count > i64::from(limit) {
            let label = match (scope, window) {
                ("envelopes_device", _) => "device_hour",
                (_, Window::Hour) => "account_hour",
                (_, Window::Day) => "account_day",
            };
            exceeded = Some((left, label));
            break;
        }
    }
    if let Some((retry_after, limit)) = exceeded {
        // Nothing of this attempt is kept: a refused hand-out never counts.
        drop(tx);
        metrics::counter!("cc_envelope_rate_limited_total", "limit" => limit).increment(1);
        AuditEvent::new(AuditType::EnvelopeRateLimited)
            .user(auth.user_id)
            .device(auth.device_id)
            .target(vault_id)
            .ip(ip)
            .meta(serde_json::json!({ "endpoint": endpoint, "limit": limit }))
            .record(&state.db)
            .await?;
        if let Err(err) = abuse_mail(state, auth).await {
            tracing::warn!(code = ?err.code(), "envelope abuse mail failed");
        }
        return Err(AppError::envelope_rate_limited(retry_after));
    }
    AuditEvent::new(AuditType::EnvelopeIssued)
        .user(auth.user_id)
        .device(auth.device_id)
        .target(vault_id)
        .ip(ip)
        .meta(serde_json::json!({ "endpoint": endpoint }))
        .record(&mut *tx)
        .await?;
    tx.commit().await?;
    metrics::counter!("cc_envelope_untrusted_issued_total").increment(1);
    Ok(())
}

/// TR-10: the first refused hand-out of a UTC day mails the owner.
async fn abuse_mail(state: &AppState, auth: &AuthContext) -> AppResult<()> {
    if !state.mailer.delivers() {
        return Ok(());
    }
    let mut tx = state.db.begin().await?;
    let (count, _) = bump(
        &mut tx,
        "envelope_abuse_mail",
        Uuid::from(auth.user_id),
        Window::Day,
    )
    .await?;
    if count != 1 {
        return Ok(());
    }
    let (email, name): (String, String) = sqlx::query_as(
        "SELECT u.email, d.name FROM users u JOIN devices d ON d.user_id = u.id
          WHERE u.id = $1 AND d.id = $2",
    )
    .bind(Uuid::from(auth.user_id))
    .bind(Uuid::from(auth.device_id))
    .fetch_one(&mut *tx)
    .await?;
    let token = issue_deny_token(&mut tx, auth.user_id, Some(auth.device_id)).await?;
    tx.commit().await?;
    mail::send_in_background(
        state.mailer.clone(),
        templates::envelope_abuse(
            &email,
            &name,
            token.token.expose_secret(),
            state.config.public_url.as_deref(),
        ),
    );
    Ok(())
}

/// TR-1/TR-3 after a login created `reg` for `user_id`: the
/// `device_registered` event and the throttled "new device" mail. Never fails
/// the login.
pub async fn on_device_created(
    state: &AppState,
    user_id: UserId,
    reg: &DeviceRegistration,
    ip: Option<IpAddr>,
) {
    let prot = &state.config.device_protection;
    if !prot.enabled {
        return;
    }
    if let Err(err) = notify_new_device(state, user_id, reg, ip).await {
        tracing::warn!(code = ?err.code(), "new device notification failed");
    }
}

async fn notify_new_device(
    state: &AppState,
    user_id: UserId,
    reg: &DeviceRegistration,
    ip: Option<IpAddr>,
) -> AppResult<()> {
    let prot = &state.config.device_protection;
    let (email, name, created_at, client_version): (String, String, DateTime<Utc>, Option<String>) =
        sqlx::query_as(
            "SELECT u.email, d.name, d.created_at, d.client_version
               FROM devices d JOIN users u ON u.id = d.user_id
              WHERE d.id = $1 AND d.user_id = $2",
        )
        .bind(Uuid::from(reg.device_id))
        .bind(Uuid::from(user_id))
        .fetch_one(&state.db)
        .await?;
    state
        .events
        .publish_user(
            user_id,
            ServerEvent::DeviceRegistered {
                device_id: reg.device_id,
                name: name.clone(),
                platform: reg.platform,
                created_at,
            },
        )
        .await;
    if !prot.new_device_mail || !state.mailer.delivers() {
        return Ok(());
    }
    let mut tx = state.db.begin().await?;
    let (count, _) = bump(
        &mut tx,
        "new_device_mail",
        Uuid::from(user_id),
        Window::Hour,
    )
    .await?;
    let limit = i64::from(prot.new_device_mails_per_hour);
    let info = templates::NewDeviceInfo {
        name: &name,
        platform: reg.platform.as_str(),
        client_version: client_version.as_deref(),
        at: created_at,
        ip,
    };
    let message = if limit == 0 || count <= limit {
        let token = issue_deny_token(&mut tx, user_id, Some(reg.device_id)).await?;
        Some(templates::new_device(
            &email,
            &info,
            token.token.expose_secret(),
            state.config.public_url.as_deref(),
        ))
    } else if count == limit + 1 {
        Some(templates::new_device_summary(
            &email,
            state.config.public_url.as_deref(),
        ))
    } else {
        None
    };
    tx.commit().await?;
    if let Some(message) = message {
        mail::send_in_background(state.mailer.clone(), message);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn prot(enabled: bool) -> DeviceProtectionConfig {
        let mut c = crate::Config::for_tests("postgres://localhost/unused").device_protection;
        c.enabled = enabled;
        c.quarantine = Duration::from_secs(14 * 24 * 3600);
        c
    }

    #[test]
    fn quarantine_window() {
        let now = Utc::now();
        let young = now - chrono::Duration::days(2);
        let old = now - chrono::Duration::days(15);
        let p = prot(true);
        assert_eq!(
            quarantine_end(&p, young, None, None),
            Some(young + chrono::Duration::days(14))
        );
        assert_eq!(quarantine_end(&p, old, None, None), None);
        assert_eq!(quarantine_end(&p, young, Some(now), None), None);
        assert_eq!(quarantine_end(&p, young, None, Some(now)), None);
        assert_eq!(quarantine_end(&prot(false), young, None, None), None);
    }

    #[test]
    fn trusted_predicate_is_parameterised() {
        let sql = trusted_sql("d.id");
        assert!(sql.contains("te.recipient_id = d.id"));
        assert!(sql.contains("te.revoked_at IS NULL"));
    }
}
