// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Enterprise sign-in mode (protocol 1.8, `CC_AUTH_MODE=enterprise`).
//!
//! Accounts sign in only through the organisation's identity source: an OIDC
//! IdP ([`oidc`]) or LDAP / Active Directory ([`ldap`]). Only the *account*
//! authentication changes: vaults, encryption, devices (incl. new-device
//! protection) and sharing work exactly as in standard mode, and neither the
//! IdP nor the directory nor this server ever gets anything that decrypts a
//! vault.
//!
//! * [`accounts`] links identities to accounts (ТР-3) and issues sessions;
//! * [`handlers`] serves `/v1/auth/oidc/*` and `/v1/auth/ldap/login`;
//! * [`recheck`] re-validates users at the IdP/directory (ТР-6);
//! * [`lockout`] keeps this server from locking directory accounts out.

pub mod accounts;
pub mod handlers;
pub mod jwt;
pub mod ldap;
pub mod lockout;
pub mod oidc;
pub mod recheck;
pub mod secrets;

use crate::config::{Config, ProviderKind};
use crate::error::AppError;
use cc_protocol::ErrorCode;
use serde_json::{Map, Value};
use std::fmt;
use std::sync::Arc;

/// Message of `enterprise_auth_required`: older apps show it verbatim.
pub const ENTERPRISE_AUTH_MESSAGE: &str =
    "This server uses your organization's sign-in (SSO / directory). Update the ConsoleCrypt \
     app to the latest version to sign in.";

pub fn enterprise_auth_required() -> AppError {
    AppError::new(ErrorCode::EnterpriseAuthRequired, ENTERPRISE_AUTH_MESSAGE)
}

/// The configured provider, initialised and validated.
#[derive(Debug)]
pub enum Provider {
    Oidc(oidc::OidcProvider),
    Ldap(ldap::LdapProvider),
}

#[derive(Debug)]
pub struct Enterprise {
    pub provider: Provider,
    /// Seals upstream refresh tokens (OIDC only).
    pub token_box: Option<secrets::TokenBox>,
}

impl Enterprise {
    /// Build and validate the provider (§3.5): `None` in standard mode; an
    /// error (startup fails) if the IdP/directory is misconfigured or
    /// unreachable.
    pub async fn init(config: &Config) -> anyhow::Result<Option<Arc<Self>>> {
        let auth = &config.auth;
        let Some(kind) = auth.enterprise_provider() else {
            return Ok(None);
        };
        let ent = match kind {
            ProviderKind::Oidc => {
                let cfg = auth.oidc.as_ref().expect("validated config");
                let token_box = secrets::TokenBox::from_file(&cfg.token_key_file)?;
                let public = config.public_url.as_deref().unwrap_or_default();
                let provider = oidc::OidcProvider::discover(cfg, public).await?;
                Self {
                    provider: Provider::Oidc(provider),
                    token_box: Some(token_box),
                }
            }
            ProviderKind::Ldap => {
                let cfg = auth.ldap.as_ref().expect("validated config");
                Self {
                    provider: Provider::Ldap(ldap::LdapProvider::connect(cfg).await?),
                    token_box: None,
                }
            }
        };
        Ok(Some(Arc::new(ent)))
    }

    pub fn kind(&self) -> ProviderKind {
        match self.provider {
            Provider::Oidc(_) => ProviderKind::Oidc,
            Provider::Ldap(_) => ProviderKind::Ldap,
        }
    }

    /// `account_identities.issuer` of the configured source.
    pub fn issuer(&self) -> &str {
        match &self.provider {
            Provider::Oidc(o) => &o.cfg.issuer,
            Provider::Ldap(l) => &l.issuer,
        }
    }

    pub fn oidc(&self) -> Option<&oidc::OidcProvider> {
        match &self.provider {
            Provider::Oidc(o) => Some(o),
            Provider::Ldap(_) => None,
        }
    }

    pub fn ldap(&self) -> Option<&ldap::LdapProvider> {
        match &self.provider {
            Provider::Ldap(l) => Some(l),
            Provider::Oidc(_) => None,
        }
    }

    /// Re-run the startup checks (admin CLI).
    pub async fn check(&self) -> anyhow::Result<String> {
        match &self.provider {
            Provider::Oidc(o) => o.check().await,
            Provider::Ldap(l) => l.check().await,
        }
    }
}

/// Associated data binding a sealed upstream token to its identity.
pub fn token_context(provider: ProviderKind, issuer: &str, subject: &str) -> Vec<u8> {
    format!(
        "cc-upstream-token-v1|{}|{issuer}|{subject}",
        provider.as_str()
    )
    .into_bytes()
}

/// An identity proven by the IdP or directory.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub provider: ProviderKind,
    pub issuer: String,
    pub subject: String,
    /// Email attribute, if the source provides one.
    pub email: Option<String>,
    /// The source did not say the email is unverified.
    pub email_verified: bool,
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("provider", &self.provider)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

/// Why a verified identity may not sign in. Each maps to a protocol error
/// code and a stable `details.reason` (audit and logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A token/claim problem (bad or forged ID token, missing `sub`).
    Invalid(&'static str),
    DomainNotAllowed,
    /// The identity has no email address (needed to create or link).
    EmailMissing,
    GroupRequired,
    MfaRequired,
    IdentityConflict(&'static str),
    AccountDisabled,
    /// No account and `CC_AUTH_AUTO_CREATE=false`.
    NotProvisioned,
}

impl Refusal {
    pub fn code(self) -> ErrorCode {
        match self {
            Refusal::Invalid(_) => ErrorCode::InvalidCredentials,
            Refusal::DomainNotAllowed | Refusal::EmailMissing => ErrorCode::DomainNotAllowed,
            Refusal::GroupRequired => ErrorCode::GroupRequired,
            Refusal::MfaRequired => ErrorCode::MfaRequired,
            Refusal::IdentityConflict(_) => ErrorCode::IdentityConflict,
            Refusal::AccountDisabled => ErrorCode::AccountDisabled,
            Refusal::NotProvisioned => ErrorCode::Forbidden,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Invalid(r) => r,
            Refusal::DomainNotAllowed => "domain_not_allowed",
            Refusal::EmailMissing => "email_missing",
            Refusal::GroupRequired => "group_required",
            Refusal::MfaRequired => "mfa_required",
            Refusal::IdentityConflict(r) => r,
            Refusal::AccountDisabled => "account_disabled",
            Refusal::NotProvisioned => "not_provisioned",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Refusal::Invalid(_) => "sign-in failed",
            Refusal::DomainNotAllowed => "your email domain is not allowed on this server",
            Refusal::EmailMissing => "your account has no email address in the identity provider",
            Refusal::GroupRequired => "your account is not in the group allowed to use this server",
            Refusal::MfaRequired => "multi-factor authentication is required",
            Refusal::IdentityConflict(_) => {
                "an account with this email exists and is linked to a different identity; \
                 ask the administrator"
            }
            Refusal::AccountDisabled => "access disabled by the administrator",
            Refusal::NotProvisioned => "no account for this identity; ask the administrator",
        }
    }
}

impl From<Refusal> for AppError {
    fn from(r: Refusal) -> Self {
        AppError::new(r.code(), r.message())
            .with_details(serde_json::json!({ "reason": r.reason() }))
    }
}

/// `details.reason` of an error, if any (for audit/logs).
pub fn error_reason(err: &AppError) -> &'static str {
    match err {
        AppError::Api {
            details: Some(d), ..
        } => match d.get("reason").and_then(Value::as_str) {
            // Map back to the static set so nothing request-derived is logged.
            Some(r) => STATIC_REASONS
                .iter()
                .copied()
                .find(|s| *s == r)
                .unwrap_or("other"),
            None => "other",
        },
        _ => "other",
    }
}

const STATIC_REASONS: &[&str] = &[
    "domain_not_allowed",
    "email_missing",
    "group_required",
    "mfa_required",
    "account_disabled",
    "not_provisioned",
    "linked_to_other_identity",
    "link_requires_allowed_domain",
    "email_not_verified",
    "unknown_kid",
    "bad_signature",
    "unsupported_alg",
    "malformed",
    "iss",
    "aud",
    "azp",
    "exp",
    "iat",
    "nbf",
    "nonce",
    "sub",
];

/// A string claim.
pub fn claim_str<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

/// Whether claim `name` equals `value` or (array) contains it.
pub fn claim_contains(claims: &Map<String, Value>, name: &str, value: &str) -> bool {
    fn matches(v: &Value, value: &str) -> bool {
        match v {
            Value::String(s) => s == value,
            Value::Bool(b) => b.to_string() == value,
            Value::Number(n) => n.to_string() == value,
            _ => false,
        }
    }
    match claims.get(name) {
        Some(Value::Array(items)) => items.iter().any(|v| matches(v, value)),
        Some(v) => matches(v, value),
        None => false,
    }
}

/// Persist the latest provider check for `admin auth status`.
pub async fn record_status(
    db: &sqlx::PgPool,
    provider: ProviderKind,
    ok: bool,
    detail: &str,
) -> Result<(), sqlx::Error> {
    let detail: String = detail.chars().take(500).collect();
    sqlx::query(
        "INSERT INTO auth_provider_status (singleton, provider, ok, detail, checked_at)
         VALUES (true, $1, $2, $3, now())
         ON CONFLICT (singleton) DO UPDATE
            SET provider = EXCLUDED.provider, ok = EXCLUDED.ok, detail = EXCLUDED.detail,
                checked_at = EXCLUDED.checked_at",
    )
    .bind(provider.as_str())
    .bind(ok)
    .bind(detail)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn claim_matching() {
        let c = json!({"groups": ["a", "cc-users"], "role": "admin", "flag": true, "n": 5})
            .as_object()
            .unwrap()
            .clone();
        assert!(claim_contains(&c, "groups", "cc-users"));
        assert!(!claim_contains(&c, "groups", "cc"));
        assert!(claim_contains(&c, "role", "admin"));
        assert!(claim_contains(&c, "flag", "true"));
        assert!(claim_contains(&c, "n", "5"));
        assert!(!claim_contains(&c, "missing", "x"));
    }

    #[test]
    fn refusals_map_to_protocol_codes() {
        let e: AppError = Refusal::IdentityConflict("linked_to_other_identity").into();
        assert_eq!(e.code(), ErrorCode::IdentityConflict);
        assert_eq!(error_reason(&e), "linked_to_other_identity");
        let e: AppError = Refusal::GroupRequired.into();
        assert_eq!(e.code(), ErrorCode::GroupRequired);
        assert_eq!(error_reason(&AppError::not_found()), "other");
    }
}
