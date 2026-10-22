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
    }
}
