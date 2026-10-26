//! Teams (protocol 1.10): a team is a vault of kind `team` whose VRK reaches
//! every member through a **user envelope** (`RecipientType::User`,
//! `recipient_id = user_id`) sealed to the member's per-team identity key.
//!
//! The team's membership is a hash-chained log of entries, each signed with
//! the per-team signing key of an authorized member. Clients verify the log
//! from genesis and never trust a member or key the log does not contain:
//! the server stores the entries, checks them too, but cannot add members or
//! swap keys on its own.
//!
//! Byte layouts here are normative for both server and client
//! (`team_log_message`, `team_log_hash_input`, `team_member_code_input`).

use crate::bytes::Bytes;
use crate::envelopes::{KeyEnvelope, NewEnvelope};
use crate::ids::{TeamInvitationId, UserId, VaultId};
use crate::vaults::VaultRole;
use crate::Timestamp;
use serde::{Deserialize, Serialize};

/// Current log entry format.
pub const TEAM_LOG_FORMAT: u16 = 1;
/// Ed25519 / X25519 public key length.
pub const TEAM_KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const TEAM_SIGNATURE_LEN: usize = 64;
/// SHA-256 length of `previous_hash` / log heads.
pub const TEAM_HASH_LEN: usize = 32;
/// Maximum invitation note (UTF-8 characters). The server sees it.
pub const MAX_INVITATION_NOTE_CHARS: usize = 200;
/// Maximum log entries per page.
pub const MAX_TEAM_LOG_PAGE: usize = 500;
/// Key-epoch chain link: 24-byte nonce, 32-byte VRK + 16-byte tag.
pub const TEAM_CHAIN_NONCE_LEN: usize = 24;
pub const TEAM_CHAIN_CIPHERTEXT_LEN: usize = 48;

pub mod labels {
    /// Prefix of the signed canonical log entry.
    pub const TEAM_LOG_ENTRY: &[u8] = b"consolecrypt/teams/v1/log-entry\0";
    /// Prefix of the log hash input (entry + signature).
    pub const TEAM_LOG_HASH: &[u8] = b"consolecrypt/teams/v1/log-hash\0";
    /// Prefix of a signed team key commitment (protocol 1.12).
    pub const TEAM_KEY_COMMITMENT: &[u8] = b"consolecrypt/teams/v1/key-commitment\0";
    /// Prefix of the member verification code input.
    pub const TEAM_MEMBER_CODE: &[u8] = b"consolecrypt/teams/v1/member-code\0";
    /// Prefix of the key-epoch chain AEAD associated data.
    pub const TEAM_KEY_CHAIN: &[u8] = b"consolecrypt/teams/v1/key-chain\0";
}

/// A member's per-team public identity (X25519 encryption + Ed25519 signing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamMemberKeys {
    pub user_id: UserId,
    pub encryption_key: Bytes,
    pub signing_key: Bytes,
}

/// What a log entry does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TeamLogOp {
    /// `seq = 0`: the creator becomes owner with these keys.
    Genesis { owner: TeamMemberKeys },
    /// admin+: a new member (role never `owner`).
    AddMember {
        member: TeamMemberKeys,
        role: VaultRole,
    },
    /// admin+: change a non-owner member's role (never to `owner`).
    ChangeRole { user_id: UserId, role: VaultRole },
    /// admin+: remove a non-owner member.
    RemoveMember { user_id: UserId },
    /// Any non-owner member removes itself.
    Leave,
    /// owner: hand ownership to a member (the old owner becomes admin).
    TransferOwner { user_id: UserId },
    /// admin+: the VRK of `key_epoch` replaces the previous one.
    RotateKey { key_epoch: u32 },
}

impl TeamLogOp {
    fn tag(&self) -> u8 {
        match self {
            Self::Genesis { .. } => 1,
            Self::AddMember { .. } => 2,
            Self::ChangeRole { .. } => 3,
            Self::RemoveMember { .. } => 4,
            Self::Leave => 5,
            Self::TransferOwner { .. } => 6,
            Self::RotateKey { .. } => 7,
        }
    }
}

/// One membership log entry (unsigned part).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamLogEntry {
    pub format: u16,
    pub vault_id: VaultId,
    pub seq: u64,
    /// Hash of the previous signed entry; 32 zero bytes for genesis.
    pub previous_hash: Bytes,
    /// Unix seconds.
    pub issued_at: i64,
    pub actor_user_id: UserId,
    /// The actor's per-team signing key (must be the one in the log).
    pub actor_signing_key: Bytes,
    pub op: TeamLogOp,
}

/// A log entry with the actor's Ed25519 signature over
/// [`team_log_message`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTeamLogEntry {
    pub entry: TeamLogEntry,
    pub signature: Bytes,
}

/// Structural problem of a team record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid team record: {0}")]
pub struct TeamValidationError(pub &'static str);

fn role_tag(role: VaultRole) -> u8 {
    match role {
        VaultRole::Owner => 1,
        VaultRole::Admin => 2,
        VaultRole::Editor => 3,
        VaultRole::Viewer => 4,
    }
}

fn key32(b: &Bytes, what: &'static str) -> Result<[u8; 32], TeamValidationError> {
    b.as_slice()
        .try_into()
        .map_err(|_| TeamValidationError(what))
}

impl TeamMemberKeys {
    pub fn validate(&self) -> Result<(), TeamValidationError> {
        key32(&self.encryption_key, "encryption key must be 32 bytes")?;
        key32(&self.signing_key, "signing key must be 32 bytes")?;
        if self.user_id.as_uuid().is_nil() {
            return Err(TeamValidationError("nil user id"));
        }
        Ok(())
    }

    fn write(&self, m: &mut Vec<u8>) {
        m.extend_from_slice(self.user_id.as_bytes());
        m.extend_from_slice(self.encryption_key.as_slice());
        m.extend_from_slice(self.signing_key.as_slice());
    }
}

impl SignedTeamLogEntry {
    /// Structural validation (lengths, op shape). Not signature or
    /// authorization checking.
    pub fn validate(&self) -> Result<(), TeamValidationError> {
        let e = &self.entry;
        if e.format != TEAM_LOG_FORMAT {
            return Err(TeamValidationError("unsupported log format"));
        }
        if self.signature.len() != TEAM_SIGNATURE_LEN {
            return Err(TeamValidationError("signature must be 64 bytes"));
        }
        if e.previous_hash.len() != TEAM_HASH_LEN {
            return Err(TeamValidationError("previous_hash must be 32 bytes"));
        }
        key32(&e.actor_signing_key, "actor signing key must be 32 bytes")?;
        let genesis = matches!(e.op, TeamLogOp::Genesis { .. });
        if genesis != (e.seq == 0) {
            return Err(TeamValidationError("genesis must be the entry with seq 0"));
        }
        if genesis && e.previous_hash.as_slice() != [0u8; TEAM_HASH_LEN] {
            return Err(TeamValidationError("genesis previous_hash must be zero"));
        }
        match &e.op {
            TeamLogOp::Genesis { owner } => {
                owner.validate()?;
                if owner.user_id != e.actor_user_id || owner.signing_key != e.actor_signing_key {
                    return Err(TeamValidationError("genesis must be signed by the owner"));
                }
            }
            TeamLogOp::AddMember { member, role } => {
                member.validate()?;
                if *role == VaultRole::Owner {
                    return Err(TeamValidationError("a member cannot be added as owner"));
                }
            }
            TeamLogOp::ChangeRole { role, .. } if *role == VaultRole::Owner => {
                return Err(TeamValidationError(
                    "use transfer_owner to change the owner",
                ));
            }
            TeamLogOp::RotateKey { key_epoch } if *key_epoch == 0 => {
                return Err(TeamValidationError("rotated key epoch must be > 0"));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Message the actor signs with its per-team Ed25519 key.
///
/// ```text
/// TEAM_LOG_ENTRY || format (u16 BE) || vault_id (16) || seq (u64 BE)
/// || previous_hash (32) || issued_at (i64 BE) || actor_user_id (16)
/// || actor_signing_key (32) || op_tag (u8) || op fields
///
/// op fields:
///   genesis         owner: user_id (16) || encryption_key (32) || signing_key (32)
///   add_member      member keys (80) || role (u8: owner 1, admin 2, editor 3, viewer 4)
///   change_role     user_id (16) || role (u8)
///   remove_member   user_id (16)
///   leave           —
///   transfer_owner  user_id (16)
///   rotate_key      key_epoch (u32 BE)
/// ```
///
/// Call only on structurally valid entries.
pub fn team_log_message(entry: &TeamLogEntry) -> Vec<u8> {
    let mut m = Vec::with_capacity(labels::TEAM_LOG_ENTRY.len() + 200);
    m.extend_from_slice(labels::TEAM_LOG_ENTRY);
    m.extend_from_slice(&entry.format.to_be_bytes());
    m.extend_from_slice(entry.vault_id.as_bytes());
    m.extend_from_slice(&entry.seq.to_be_bytes());
    m.extend_from_slice(entry.previous_hash.as_slice());
    m.extend_from_slice(&entry.issued_at.to_be_bytes());
    m.extend_from_slice(entry.actor_user_id.as_bytes());
    m.extend_from_slice(entry.actor_signing_key.as_slice());
    m.push(entry.op.tag());
    match &entry.op {
        TeamLogOp::Genesis { owner } => owner.write(&mut m),
        TeamLogOp::AddMember { member, role } => {
            member.write(&mut m);
            m.push(role_tag(*role));
        }
        TeamLogOp::ChangeRole { user_id, role } => {
            m.extend_from_slice(user_id.as_bytes());
            m.push(role_tag(*role));
        }
        TeamLogOp::RemoveMember { user_id } | TeamLogOp::TransferOwner { user_id } => {
            m.extend_from_slice(user_id.as_bytes());
        }
        TeamLogOp::Leave => {}
        TeamLogOp::RotateKey { key_epoch } => m.extend_from_slice(&key_epoch.to_be_bytes()),
    }
    m
}

/// Input of the entry hash: `SHA-256(TEAM_LOG_HASH || message || signature)`
/// is the next entry's `previous_hash` and the log head.
pub fn team_log_hash_input(signed: &SignedTeamLogEntry) -> Vec<u8> {
    let msg = team_log_message(&signed.entry);
    let mut m = Vec::with_capacity(labels::TEAM_LOG_HASH.len() + msg.len() + 64);
    m.extend_from_slice(labels::TEAM_LOG_HASH);
    m.extend_from_slice(&msg);
    m.extend_from_slice(signed.signature.as_slice());
    m
}

/// Input of the code the inviting admin and the joining member compare:
/// `h = SHA-256(..)` rendered like the device code (6 groups of 5 digits).
///
/// ```text
/// TEAM_MEMBER_CODE || vault_id (16) || admin_signing_key (32)
/// || member user_id (16) || member encryption_key (32) || member signing_key (32)
/// ```
pub fn team_member_code_input(
    vault_id: VaultId,
    admin_signing_key: &[u8; 32],
    member: &TeamMemberKeys,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(labels::TEAM_MEMBER_CODE.len() + 128);
    m.extend_from_slice(labels::TEAM_MEMBER_CODE);
    m.extend_from_slice(vault_id.as_bytes());
    m.extend_from_slice(admin_signing_key);
    member.write(&mut m);
    m
}

/// AEAD associated data of a key-chain link (VRK of `key_epoch - 1` sealed
/// under the VRK of `key_epoch`).
///
/// ```text
/// TEAM_KEY_CHAIN || vault_id (16) || key_epoch (u32 BE)
/// ```
pub fn team_key_chain_aad(vault_id: VaultId, key_epoch: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(labels::TEAM_KEY_CHAIN.len() + 20);
    m.extend_from_slice(labels::TEAM_KEY_CHAIN);
    m.extend_from_slice(vault_id.as_bytes());
    m.extend_from_slice(&key_epoch.to_be_bytes());
    m
}

/// The previous epoch's VRK sealed under this epoch's VRK (opaque to the
/// server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamKeyChainLink {
    pub key_epoch: u32,
    pub nonce: Bytes,
    pub ciphertext: Bytes,
}

impl TeamKeyChainLink {
    pub fn validate(&self) -> Result<(), TeamValidationError> {
        if self.key_epoch == 0
            || self.nonce.len() != TEAM_CHAIN_NONCE_LEN
            || self.ciphertext.len() != TEAM_CHAIN_CIPHERTEXT_LEN
        {
            return Err(TeamValidationError("malformed key chain link"));
        }
        Ok(())
    }
}

// ---- requests / responses -------------------------------------------------------------

/// `POST /v1/teams`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTeamRequest {
    pub vault_id: VaultId,
    /// VAK of the team VRK (epoch 0).
    pub vault_access_key: Bytes,
    pub genesis: SignedTeamLogEntry,
    /// VRK sealed to the owner's per-team encryption key
    /// (`recipient_type = user`, `recipient_id = owner user id`).
    pub owner_envelope: NewEnvelope,
    /// The calling device's trust marker for the team vault.
    pub device_envelope: NewEnvelope,
    /// Protocol 1.12: the owner's signed commitment of the epoch-0 VRK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<TeamKeyCommitment>,
}

/// A team as the caller sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamInfo {
    pub vault_id: VaultId,
    pub role: VaultRole,
    pub key_epoch: u32,
    pub log_seq: u64,
    /// Hash of the last log entry.
    pub log_head: Bytes,
    pub members_count: u32,
    /// A member left or was removed: an admin client should rotate the key.
    pub rotation_required: bool,
    /// The calling device holds a trust marker for the team vault.
    pub caller_trusted: bool,
    pub latest_sequence: i64,
    pub epoch: uuid::Uuid,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// A member with the keys the log pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamMember {
    pub user_id: UserId,
    pub email: String,
    pub role: VaultRole,
    pub encryption_key: Bytes,
    pub signing_key: Bytes,
    pub joined_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTeamsResponse {
    pub teams: Vec<TeamInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamDetail {
    pub team: TeamInfo,
    pub members: Vec<TeamMember>,
}

/// `GET /v1/teams/{vault_id}/log?after=<seq>` (exclusive; omit for all).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamLogQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamLogPage {
    pub entries: Vec<SignedTeamLogEntry>,
    pub head_seq: u64,
    pub has_more: bool,
}

/// `GET /v1/teams/{vault_id}/key`: the caller's user envelope for the
/// current epoch and the chain links back to epoch 0 (newest first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamKeyMaterial {
    pub key_epoch: u32,
    pub envelope: KeyEnvelope,
    pub chain: Vec<TeamKeyChainLink>,
    /// Protocol 1.12: the signed commitment of the `key_epoch` VRK, if an
    /// admin published one. Clients check it against the key they opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<TeamKeyCommitment>,
}

/// Protocol 1.12: an owner or admin vouches for the VRK of `key_epoch` by
/// signing its key commitment (`HKDF(VRK)`, the same value as the vault key
/// commitment of protocol 1.11) with their per-team signing key from the
/// membership log. A member opening the team checks the signature with the
/// signer's key from the log it verified, so a server cannot hand out a
/// VRK of its own — not even to a member opening the team for the first
/// time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamKeyCommitment {
    pub key_epoch: u32,
    /// 32 bytes.
    pub commitment: Bytes,
    /// An owner or admin of the team.
    pub signer_user_id: UserId,
    /// Ed25519 over [`team_key_commitment_message`].
    pub signature: Bytes,
}

/// Canonical signed bytes of a team key commitment:
///
/// ```text
/// TEAM_KEY_COMMITMENT || vault_id (16) || key_epoch (u32 BE)
/// || commitment (32) || signer_user_id (16)
/// ```
pub fn team_key_commitment_message(
    vault_id: VaultId,
    key_epoch: u32,
    commitment: &[u8],
    signer_user_id: UserId,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(labels::TEAM_KEY_COMMITMENT.len() + 72);
    m.extend_from_slice(labels::TEAM_KEY_COMMITMENT);
    m.extend_from_slice(vault_id.as_bytes());
    m.extend_from_slice(&key_epoch.to_be_bytes());
    m.extend_from_slice(commitment);
    m.extend_from_slice(signer_user_id.as_bytes());
    m
}

impl TeamKeyCommitment {
    /// Structural checks (sizes only; the signature is the reader's job).
    pub fn validate(&self) -> Result<(), TeamValidationError> {
        if self.commitment.len() != 32 || self.signature.len() != 64 {
            return Err(TeamValidationError("malformed team key commitment"));
        }
        Ok(())
    }
}

/// `PUT /v1/teams/{vault_id}/key-commitment` → `204` (protocol 1.12): an
/// owner or admin publishes (or replaces) the commitment of the current
/// key epoch, e.g. for a team created before 1.12.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutTeamKeyCommitmentRequest {
    /// VAK of the current epoch.
    pub vault_access_key: Bytes,
    pub key_commitment: TeamKeyCommitment,
}

/// `POST /v1/teams/{vault_id}/invitations` → `202`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteTeamMemberRequest {
    pub email: String,
    pub role: VaultRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamInvitationStatus {
    /// Waiting for the invitee.
    Pending,
    /// The invitee submitted keys; waiting for the inviter's code check.
    Accepted,
    /// The inviter added the member.
    Completed,
    Declined,
    Cancelled,
    Expired,
}

/// An invitation (incoming for the invitee, outgoing for admins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamInvitation {
    pub invitation_id: TeamInvitationId,
    pub vault_id: VaultId,
    pub inviter_user_id: UserId,
    pub inviter_email: String,
    /// The inviter's per-team signing key (input of the member code).
    pub inviter_signing_key: Bytes,
    pub invitee_user_id: UserId,
    pub invitee_email: String,
    pub role: VaultRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub status: TeamInvitationStatus,
    /// The invitee's keys once accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_keys: Option<TeamMemberKeys>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTeamInvitationsResponse {
    pub invitations: Vec<TeamInvitation>,
}

/// `POST /v1/teams/invitations/{invitation_id}/accept`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptTeamInvitationRequest {
    pub encryption_key: Bytes,
    pub signing_key: Bytes,
}

/// `POST /v1/teams/{vault_id}/log`: append one signed entry with its effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTeamLogRequest {
    pub entry: SignedTeamLogEntry,
    /// VAK of the current epoch (proves the actor holds the team key).
    pub vault_access_key: Bytes,
    /// `add_member`: the completed invitation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_id: Option<TeamInvitationId>,
    /// `add_member`: one user envelope for the new member.
    /// `rotate_key`: one user envelope (new epoch) per remaining member.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envelopes: Vec<NewEnvelope>,
    /// `rotate_key`: VAK of the new VRK and the chain link to the old one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_vault_access_key: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_link: Option<TeamKeyChainLink>,
    /// `rotate_key` (protocol 1.12): the actor's signed commitment of the
    /// new epoch's VRK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<TeamKeyCommitment>,
}

/// Result of `POST /v1/teams/{vault_id}/log`. `team` is absent when the
/// caller is no longer a member (it left).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTeamLogResponse {
    pub log_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<TeamInfo>,
    pub members: Vec<TeamMember>,
}

#[cfg(test)]
mod tests {

    #[test]
    fn team_key_commitment_message_layout_1_12() {
        let vault = VaultId::new();
        let signer = UserId::new();
        let m = team_key_commitment_message(vault, 7, &[9u8; 32], signer);
        let label = labels::TEAM_KEY_COMMITMENT;
        assert!(m.starts_with(label));
        assert_eq!(m.len(), label.len() + 16 + 4 + 32 + 16);
        assert_eq!(&m[label.len()..label.len() + 16], vault.as_bytes());
        assert_eq!(&m[label.len() + 16..label.len() + 20], &7u32.to_be_bytes());
        let kc = TeamKeyCommitment {
            key_epoch: 7,
            commitment: Bytes::new(vec![1; 32]),
            signer_user_id: signer,
            signature: Bytes::new(vec![2; 64]),
        };
        assert!(kc.validate().is_ok());
        assert!(TeamKeyCommitment {
            commitment: Bytes::new(vec![1; 31]),
            ..kc.clone()
        }
        .validate()
        .is_err());
    }

    use super::*;

    fn keys(b: u8) -> TeamMemberKeys {
        TeamMemberKeys {
            user_id: UserId::new(),
            encryption_key: Bytes::new(vec![b; 32]),
            signing_key: Bytes::new(vec![b + 1; 32]),
        }
    }

    fn genesis() -> SignedTeamLogEntry {
        let owner = keys(1);
        SignedTeamLogEntry {
            entry: TeamLogEntry {
                format: TEAM_LOG_FORMAT,
                vault_id: VaultId::new(),
                seq: 0,
                previous_hash: Bytes::new(vec![0; 32]),
                issued_at: 1_700_000_000,
                actor_user_id: owner.user_id,
                actor_signing_key: owner.signing_key.clone(),
                op: TeamLogOp::Genesis { owner },
            },
            signature: Bytes::new(vec![9; 64]),
        }
    }

    #[test]
    fn genesis_rules() {
        let g = genesis();
        g.validate().unwrap();
        let mut bad = g.clone();
        bad.entry.seq = 1;
        assert!(bad.validate().is_err());
        let mut bad = g.clone();
        bad.entry.actor_user_id = UserId::new();
        assert!(bad.validate().is_err(), "signed by someone else");
        let mut bad = g;
        bad.signature = Bytes::new(vec![0; 63]);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn op_rules_and_message_binding() {
        let g = genesis();
        let mut add = g.clone();
        add.entry.seq = 1;
        add.entry.previous_hash = Bytes::new(vec![7; 32]);
        add.entry.op = TeamLogOp::AddMember {
            member: keys(5),
            role: VaultRole::Editor,
        };
        add.validate().unwrap();
        let m1 = team_log_message(&add.entry);
        if let TeamLogOp::AddMember { role, .. } = &mut add.entry.op {
            *role = VaultRole::Viewer;
        }
        assert_ne!(m1, team_log_message(&add.entry), "role is signed");
        if let TeamLogOp::AddMember { role, .. } = &mut add.entry.op {
            *role = VaultRole::Owner;
        }
        assert!(add.validate().is_err());
        let mut rot = g.clone();
        rot.entry.seq = 2;
        rot.entry.op = TeamLogOp::RotateKey { key_epoch: 0 };
        assert!(rot.validate().is_err());
        assert!(team_log_hash_input(&g).ends_with(&[9; 64]));
    }

    #[test]
    fn wire_shapes() {
        let op = TeamLogOp::ChangeRole {
            user_id: UserId::new(),
            role: VaultRole::Viewer,
        };
        let v = serde_json::to_value(&op).unwrap();
        assert_eq!(v["type"], "change_role");
        assert_eq!(v["role"], "viewer");
        assert_eq!(
            serde_json::to_value(TeamLogOp::Leave).unwrap(),
            serde_json::json!({"type": "leave"})
        );
        let code = team_member_code_input(VaultId::new(), &[3; 32], &keys(4));
        assert_eq!(code.len(), labels::TEAM_MEMBER_CODE.len() + 128);
    }
}
