//! Realtime events over `GET /v1/events/ws` (WebSocket, text frames, JSON).
//!
//! Authentication: `Authorization: Bearer <access token>` on the upgrade
//! request. Events carry metadata only — never ciphertext — and are hints:
//! after `vault_changed` the client runs a normal `changes` pull. Clients MUST
//! ignore unknown event types (they deserialize as [`ServerEvent::Unknown`]).
//!
//! Close codes (server → client):
//! * [`CLOSE_REVOKED`] `4001` — session or device revoked: stop, do not reconnect,
//!   surface to the user (re-login or new device identity);
//! * [`CLOSE_LAGGED`] `4002` — client fell behind the event buffer: reconnect
//!   immediately and run a normal `changes` pull;
//! * [`CLOSE_TOKEN_EXPIRED`] `4003` — the access token the socket was opened
//!   with expired or was rotated: refresh if needed and reconnect (1.4).

use crate::envelopes::RecipientType;
use crate::ids::{DeviceId, DeviceRequestId, SessionId, TeamInvitationId, VaultId};
use crate::version::{Platform, ProtocolVersion};
use crate::Timestamp;
use serde::{Deserialize, Serialize};

/// WebSocket close code: session or device revoked.
pub const CLOSE_REVOKED: u16 = 4001;
/// WebSocket close code: event buffer overflow, reconnect and pull.
pub const CLOSE_LAGGED: u16 = 4002;
/// WebSocket close code: the connecting access token expired or was rotated;
/// reconnect with the current token (protocol 1.4).
pub const CLOSE_TOKEN_EXPIRED: u16 = 4003;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    /// First frame after the upgrade.
    Hello {
        protocol_version: ProtocolVersion,
        server_time: Timestamp,
        session_id: SessionId,
    },
    VaultChanged {
        vault_id: VaultId,
        latest_sequence: i64,
    },
    DeviceAdded {
        device_id: DeviceId,
    },
    /// A new device signed in to the account (protocol 1.7, only while
    /// device protection is on). Sent in addition to `device_added`. Trusted
    /// devices offer "Revoke" / "It's me".
    DeviceRegistered {
        device_id: DeviceId,
        name: String,
        platform: Platform,
        created_at: Timestamp,
    },
    DeviceApprovalRequested {
        request_id: DeviceRequestId,
        device_id: DeviceId,
    },
    DeviceApproved {
        device_id: DeviceId,
        vault_ids: Vec<VaultId>,
    },
    /// A trusted device announced it is approving a request (protocol
    /// 1.11): the new device fetches its trust request and shows the
    /// pairing code v2.
    DeviceApprovalIntent {
        request_id: DeviceRequestId,
        device_id: DeviceId,
        approver_device_id: DeviceId,
    },
    DeviceRevoked {
        device_id: DeviceId,
    },
    RecoveryChanged {
        vault_id: VaultId,
        recipient_type: RecipientType,
    },
    SessionRevoked {
        session_id: SessionId,
    },
    TeamMembershipChangedFuture {
        vault_id: VaultId,
    },
    /// Teams (protocol 1.10): the caller was invited into a team.
    TeamInvitationReceived {
        invitation_id: TeamInvitationId,
    },
    /// An invitee accepted: the inviter compares the member code.
    TeamJoinRequested {
        vault_id: VaultId,
        invitation_id: TeamInvitationId,
    },
    /// The membership log grew (member added, role changed, left, …).
    TeamMembershipChanged {
        vault_id: VaultId,
        log_seq: u64,
    },
    /// The team key was rotated; fetch `GET /v1/teams/{id}/key`.
    TeamKeyRotated {
        vault_id: VaultId,
        key_epoch: u32,
    },
    /// The caller is no longer a member (removed, left, team deleted).
    TeamRemoved {
        vault_id: VaultId,
    },
    /// Forward compatibility: any event type this build does not know.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_changed_matches_spec_shape() {
        let vault_id = VaultId::new();
        let e = ServerEvent::VaultChanged {
            vault_id,
            latest_sequence: 1042,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "type": "vault_changed",
                "vault_id": vault_id.to_string(),
                "latest_sequence": 1042
            })
        );
    }

    #[test]
    fn device_registered_shape() {
        let device_id = DeviceId::new();
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-21T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let e = ServerEvent::DeviceRegistered {
            device_id,
            name: "Laptop".into(),
            platform: Platform::Linux,
            created_at: at,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "device_registered");
        assert_eq!(v["platform"], "linux");
        assert_eq!(serde_json::from_value::<ServerEvent>(v).unwrap(), e);
    }

    #[test]
    fn approval_intent_shape() {
        let e = ServerEvent::DeviceApprovalIntent {
            request_id: DeviceRequestId::new(),
            device_id: DeviceId::new(),
            approver_device_id: DeviceId::new(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "device_approval_intent");
        assert_eq!(serde_json::from_value::<ServerEvent>(v).unwrap(), e);
    }

    #[test]
    fn unknown_events_are_tolerated() {
        let e: ServerEvent = serde_json::from_str(r#"{"type":"something_new","x":1}"#).unwrap();
        assert_eq!(e, ServerEvent::Unknown);
    }
}
