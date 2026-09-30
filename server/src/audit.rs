// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Security audit trail (`audit_events`). Metadata only: ids, counts, types.
//! Never content, tokens, passwords, envelopes or ciphertext.

use crate::error::{current_request_id, AppResult};
use cc_protocol::{DeviceId, UserId};
use serde_json::Value;
use std::net::IpAddr;
use uuid::Uuid;

/// Audit event types. Stable strings — dashboards and retention rely on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditType {
    Register,
    Login,
    LoginFailed,
    DeviceProofFailed,
    Logout,
    RefreshTokenReuse,
    PasswordChanged,
    PasswordResetRequested,
    PasswordReset,
    AccountRecoveryStarted,
    AccountRecoveryCompleted,
    EmailVerified,
    DeviceAdded,
    DeviceTrustRequested,
    DeviceApproved,
    DeviceApprovalFailed,
    DeviceRejected,
    DeviceAttested,
    DeviceAttestFailed,
    DeviceRevoked,
    DeviceRenamed,
    VaultCreated,
    VaultDeleted,
    EnvelopeCreated,
    EnvelopeDeleted,
    EnvelopeReplaced,
    VaultProofFailed,
    SyncPush,
    AdminAction,
    ShareCreated,
    ShareAccessRotated,
    ShareRevision,
    ShareEnrollmentGrant,
    ShareEnrollmentRequest,
    ShareEnrollmentChallenge,
    ShareEnrollmentResponse,
    ShareEnrollmentAccepted,
}

impl AuditType {
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditType::Register => "register",
            AuditType::Login => "login",
            AuditType::LoginFailed => "login_failed",
            AuditType::DeviceProofFailed => "device_proof_failed",
            AuditType::Logout => "logout",
            AuditType::RefreshTokenReuse => "refresh_token_reuse",
            AuditType::PasswordChanged => "password_changed",
            AuditType::PasswordResetRequested => "password_reset_requested",
            AuditType::PasswordReset => "password_reset",
            AuditType::AccountRecoveryStarted => "account_recovery_started",
            AuditType::AccountRecoveryCompleted => "account_recovery_completed",
            AuditType::EmailVerified => "email_verified",
            AuditType::DeviceAdded => "device_added",
            AuditType::DeviceTrustRequested => "device_trust_requested",
            AuditType::DeviceApproved => "device_approved",
            AuditType::DeviceApprovalFailed => "device_approval_failed",
            AuditType::DeviceRejected => "device_rejected",
            AuditType::DeviceAttested => "device_attested",
            AuditType::DeviceAttestFailed => "device_attest_failed",
            AuditType::DeviceRevoked => "device_revoked",
            AuditType::DeviceRenamed => "device_renamed",
            AuditType::VaultCreated => "vault_created",
            AuditType::VaultDeleted => "vault_deleted",
            AuditType::EnvelopeCreated => "envelope_created",
            AuditType::EnvelopeDeleted => "envelope_deleted",
            AuditType::EnvelopeReplaced => "envelope_replaced",
            AuditType::VaultProofFailed => "vault_proof_failed",
            AuditType::SyncPush => "sync_push",
            AuditType::AdminAction => "admin_action",
            AuditType::ShareCreated => "share_created",
            AuditType::ShareAccessRotated => "share_access_rotated",
            AuditType::ShareRevision => "share_revision",
            AuditType::ShareEnrollmentGrant => "share_enrollment_grant",
            AuditType::ShareEnrollmentRequest => "share_enrollment_request",
            AuditType::ShareEnrollmentChallenge => "share_enrollment_challenge",
            AuditType::ShareEnrollmentResponse => "share_enrollment_response",
            AuditType::ShareEnrollmentAccepted => "share_enrollment_accepted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: AuditType,
    pub user_id: Option<UserId>,
    pub device_id: Option<DeviceId>,
    pub target_id: Option<Uuid>,
    pub ip: Option<IpAddr>,
    pub metadata: Value,
}

impl AuditEvent {
    pub fn new(event_type: AuditType) -> Self {
        Self {
            event_type,
            user_id: None,
            device_id: None,
            target_id: None,
            ip: None,
            metadata: Value::Object(Default::default()),
        }
    }

    pub fn user(mut self, id: UserId) -> Self {
        self.user_id = Some(id);
        self
    }

    pub fn device(mut self, id: DeviceId) -> Self {
        self.device_id = Some(id);
        self
    }

    pub fn target(mut self, id: impl Into<Uuid>) -> Self {
        self.target_id = Some(id.into());
        self
    }

    pub fn ip(mut self, ip: Option<IpAddr>) -> Self {
        self.ip = ip;
        self
    }

    pub fn meta(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Insert the event using `executor` (a transaction when the audited
    /// action is transactional, so both commit or neither does).
    pub async fn record<'e, E>(self, executor: E) -> AppResult<()>
    where
        E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO audit_events
                 (id, event_type, user_id, device_id, target_id, request_id, ip_address, metadata)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(Uuid::now_v7())
        .bind(self.event_type.as_str())
        .bind(self.user_id.map(Uuid::from))
        .bind(self.device_id.map(Uuid::from))
        .bind(self.target_id)
        .bind(current_request_id().map(Uuid::from))
        .bind(self.ip.map(|ip| ip.to_string()))
        .bind(self.metadata)
        .execute(executor)
        .await?;
        Ok(())
    }
}
