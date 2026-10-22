//! Server metadata: `GET /v1/meta` (unauthenticated).

use crate::version::ProtocolVersion;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server build version (semver).
    pub server_version: String,
    /// Protocol version the server speaks.
    pub protocol_version: ProtocolVersion,
    /// Oldest client protocol still accepted.
    pub minimum_supported_protocol: ProtocolVersion,
    /// True when the requesting client (per its headers) must upgrade.
    #[serde(default)]
    pub upgrade_required: bool,
    /// Whether new accounts can self-register on this instance
    /// (self-hosters may run invite-only / single-user instances).
    #[serde(default = "default_true")]
    pub registration_open: bool,
    /// Whether login requires a verified email.
    #[serde(default)]
    pub email_verification_required: bool,
    /// Where users of this instance can obtain the exact source code it runs.
    /// The server is AGPL-3.0 (ADR-0005): operators of modified builds must
    /// point this at their modified source. Clients show it in "About server".
    /// Added in protocol 1.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_code_url: Option<String>,
    /// Optional server features (protocol 1.7). Absent on older servers,
    /// which decode as "everything off".
    #[serde(default)]
    pub capabilities: ServerCapabilities,
}

/// Features a client may rely on only when advertised (protocol 1.7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// New-device protection is on: `DeviceInfo.trusted` /
    /// `quarantine_until` are meaningful, the server emits
    /// `device_registered`, and may answer `device_in_quarantine` /
    /// `envelope_rate_limited`.
    #[serde(default)]
    pub device_protection: bool,
    /// A recipient may leave a shared item (`POST /v1/shares/{id}/leave`,
    /// protocol 1.8). Only shared-item owners may delete it.
    #[serde(default)]
    pub share_leave: bool,
    /// A deleted shared item stays restorable by its owner for
    /// [`crate::sharing::RESTORE_WINDOW_DAYS`] (`GET /v1/shares/deleted`,
    /// `CreateShareRequest.restored_from`, protocol 1.8).
    #[serde(default)]
    pub share_restore: bool,
    /// Sharing recipient lookup by `POST /v1/shares/recipients/lookup`
    /// with the e-mail in the body (protocol 1.8); clients then stop
    /// putting the address into `GET /v1/shares/recipients?email=`.
    #[serde(default)]
    pub recipient_lookup_post: bool,
    /// How accounts sign in (protocol 1.9). Older servers omit it, which
    /// decodes as `standard` (email + account password).
    #[serde(default)]
    pub auth: AuthCapability,
}

/// `capabilities.auth` (protocol 1.9): the sign-in method of this server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCapability {
    pub mode: AuthMode,
    /// Set in enterprise mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AuthProvider>,
    /// Operator-chosen name for the sign-in button ("Sign in with
    /// {display_name}"), e.g. "Acme SSO". Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl AuthCapability {
    pub fn is_enterprise(&self) -> bool {
        self.mode == AuthMode::Enterprise
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Email + account password, registration, email verification, reset.
    #[default]
    Standard,
    /// Sign-in only through the organisation's IdP (OIDC) or directory
    /// (LDAP); see [`crate::enterprise_auth`].
    Enterprise,
    /// A mode added after this build; the client cannot sign in and should
    /// ask the user to update the app.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProvider {
    /// OpenID Connect via the system browser (`/v1/auth/oidc/*`).
    Oidc,
    /// Directory login and password (`/v1/auth/ldap/login`).
    Ldap,
    /// A provider added after this build (update the app).
    #[serde(other)]
    Unknown,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_info_from_1_0_server_still_parses() {
        let v = serde_json::json!({
            "server_version": "0.1.0",
            "protocol_version": "1.0",
            "minimum_supported_protocol": "1.0"
        });
        let info: ServerInfo = serde_json::from_value(v).unwrap();
        assert!(info.registration_open);
        assert!(info.source_code_url.is_none());
        assert!(!info.capabilities.device_protection);
        assert!(!info.capabilities.share_leave);
        assert!(!info.capabilities.share_restore);
    }

    #[test]
    fn capabilities_roundtrip() {
        let v = serde_json::json!({
            "server_version": "0.1.16",
            "protocol_version": "1.7",
            "minimum_supported_protocol": "1.0",
            "capabilities": { "device_protection": true, "future_flag": 1 }
        });
        let info: ServerInfo = serde_json::from_value(v).unwrap();
        assert!(info.capabilities.device_protection);
        assert!(!info.capabilities.share_leave);
        assert_eq!(info.capabilities.auth.mode, AuthMode::Standard);
        assert!(!info.capabilities.auth.is_enterprise());
    }

    #[test]
    fn share_capabilities_1_8() {
        let v = serde_json::json!({
            "server_version": "0.1.17",
            "protocol_version": "1.8",
            "minimum_supported_protocol": "1.0",
            "capabilities": { "share_leave": true, "share_restore": true }
        });
        let info: ServerInfo = serde_json::from_value(v).unwrap();
        assert!(info.capabilities.share_leave);
        assert!(info.capabilities.share_restore);
        assert!(!info.capabilities.device_protection);
        assert!(!info.capabilities.recipient_lookup_post);
    }

    #[test]
    fn auth_capability_1_9() {
        let v = serde_json::json!({
            "server_version": "0.2.0",
            "protocol_version": "1.9",
            "minimum_supported_protocol": "1.0",
            "capabilities": {
                "device_protection": true,
                "auth": { "mode": "enterprise", "provider": "oidc", "display_name": "Acme SSO" }
            }
        });
        let info: ServerInfo = serde_json::from_value(v).unwrap();
        let auth = &info.capabilities.auth;
        assert!(auth.is_enterprise());
        assert_eq!(auth.provider, Some(AuthProvider::Oidc));
        assert_eq!(auth.display_name.as_deref(), Some("Acme SSO"));

        let std = serde_json::to_value(AuthCapability::default()).unwrap();
        assert_eq!(std, serde_json::json!({ "mode": "standard" }));

        let future: AuthCapability =
            serde_json::from_value(serde_json::json!({ "mode": "passkeys", "provider": "x" }))
                .unwrap();
        assert_eq!(future.mode, AuthMode::Unknown);
        assert_eq!(future.provider, Some(AuthProvider::Unknown));
    }
}
