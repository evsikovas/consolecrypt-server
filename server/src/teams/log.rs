// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Server-side check of a membership log append (protocol 1.9).
//!
//! Clients verify the whole log themselves and never trust the server for
//! membership; this check keeps the stored log well-formed and refuses
//! entries the server's own state does not authorize.

use crate::crypto;
use crate::error::{AppError, AppResult};
use cc_protocol::teams::{
    team_log_hash_input, team_log_message, SignedTeamLogEntry, TeamLogOp, TEAM_HASH_LEN,
};
use cc_protocol::vaults::VaultRole;
use cc_protocol::{UserId, VaultId};
use std::collections::HashMap;

/// Accepted clock skew of `issued_at` (seconds).
pub const MAX_ENTRY_SKEW_SECONDS: i64 = 24 * 60 * 60;

/// A live member as the server stores it.
#[derive(Debug, Clone)]
pub struct LiveMember {
    pub role: VaultRole,
    pub signing_key: Vec<u8>,
}

/// The team state an append is checked against.
#[derive(Debug, Clone)]
pub struct LogState {
    pub vault_id: VaultId,
    pub log_seq: u64,
    pub log_head: [u8; TEAM_HASH_LEN],
    pub key_epoch: u32,
    pub members: HashMap<UserId, LiveMember>,
}

fn rejected(message: &'static str) -> AppError {
    AppError::forbidden(message).with_details(serde_json::json!({"reason": "team_log"}))
}

/// SHA-256 log hash of a signed entry.
pub fn entry_hash(signed: &SignedTeamLogEntry) -> [u8; TEAM_HASH_LEN] {
    crypto::sha256(&team_log_hash_input(signed))
}

/// Verify the genesis entry of a new team created by `actor`.
pub fn check_genesis(
    vault_id: VaultId,
    actor: UserId,
    signed: &SignedTeamLogEntry,
    now: i64,
) -> AppResult<[u8; TEAM_HASH_LEN]> {
    signed
        .validate()
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    let e = &signed.entry;
    if e.vault_id != vault_id || e.actor_user_id != actor {
        return Err(rejected(
            "genesis must be for this team and signed by its creator",
        ));
    }
    if !matches!(e.op, TeamLogOp::Genesis { .. }) {
        return Err(AppError::bad_request("the first entry must be genesis"));
    }
    check_time(e.issued_at, now)?;
    check_signature(e.actor_signing_key.as_slice(), signed)?;
    Ok(entry_hash(signed))
}

fn check_time(issued_at: i64, now: i64) -> AppResult<()> {
    if (issued_at - now).abs() > MAX_ENTRY_SKEW_SECONDS {
        return Err(AppError::bad_request("log entry time is out of range"));
    }
    Ok(())
}

fn check_signature(signing_key: &[u8], signed: &SignedTeamLogEntry) -> AppResult<()> {
    if !crypto::verify_ed25519(
        signing_key,
        &team_log_message(&signed.entry),
        signed.signature.as_slice(),
    ) {
        return Err(rejected("log entry signature is invalid"));
    }
    Ok(())
}

fn admin(role: VaultRole) -> bool {
    matches!(role, VaultRole::Owner | VaultRole::Admin)
}

/// Verify that `actor` may append `signed` to `state`. Returns the new head.
pub fn check_append(
    state: &LogState,
    actor: UserId,
    signed: &SignedTeamLogEntry,
    now: i64,
) -> AppResult<[u8; TEAM_HASH_LEN]> {
    signed
        .validate()
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    let e = &signed.entry;
    if e.vault_id != state.vault_id {
        return Err(AppError::bad_request("log entry belongs to another team"));
    }
    if e.seq != state.log_seq + 1 || e.previous_hash.as_slice() != state.log_head {
        return Err(AppError::new(
            cc_protocol::ErrorCode::Conflict,
            "the team log changed; reload it and try again",
        )
        .with_details(serde_json::json!({"reason": "team_log_head", "log_seq": state.log_seq})));
    }
    if e.actor_user_id != actor {
        return Err(rejected("log entries are signed by the calling member"));
    }
    let me = state
        .members
        .get(&actor)
        .ok_or_else(|| rejected("not a member"))?;
    if !crypto::ct_eq(&me.signing_key, e.actor_signing_key.as_slice()) {
        return Err(rejected("signing key does not match the member's key"));
    }
    check_time(e.issued_at, now)?;
    check_signature(&me.signing_key, signed)?;
    let target_live = |user: &UserId| state.members.get(user);
    match &e.op {
        TeamLogOp::Genesis { .. } => return Err(AppError::bad_request("genesis exists")),
        TeamLogOp::AddMember { member, .. } => {
            if !admin(me.role) {
                return Err(rejected("only admins add members"));
            }
            if target_live(&member.user_id).is_some() {
                return Err(AppError::already_exists("user_id", "already a member"));
            }
        }
        TeamLogOp::ChangeRole { user_id, .. } => {
            if !admin(me.role) {
                return Err(rejected("only admins change roles"));
            }
            match target_live(user_id) {
                None => return Err(AppError::not_found()),
                Some(t) if t.role == VaultRole::Owner => {
                    return Err(rejected("the owner's role changes only by transfer"))
                }
                Some(t) if t.role == VaultRole::Admin && me.role != VaultRole::Owner => {
                    return Err(rejected("only the owner changes an admin's role"))
                }
                _ => {}
            }
        }
        TeamLogOp::RemoveMember { user_id } => {
            if !admin(me.role) {
                return Err(rejected("only admins remove members"));
            }
            match target_live(user_id) {
                None => return Err(AppError::not_found()),
                Some(t) if t.role == VaultRole::Owner => {
                    return Err(rejected("the owner cannot be removed"))
                }
                Some(t) if t.role == VaultRole::Admin && me.role != VaultRole::Owner => {
                    return Err(rejected("only the owner removes an admin"))
                }
                _ => {}
            }
        }
        TeamLogOp::Leave => {
            if me.role == VaultRole::Owner {
                return Err(rejected("the owner transfers ownership before leaving"));
            }
        }
        TeamLogOp::TransferOwner { user_id } => {
            if me.role != VaultRole::Owner {
                return Err(rejected("only the owner transfers ownership"));
            }
            if *user_id == actor || target_live(user_id).is_none() {
                return Err(AppError::bad_request("transfer to another member"));
            }
        }
        TeamLogOp::RotateKey { key_epoch } => {
            if !admin(me.role) {
                return Err(rejected("only admins rotate the team key"));
            }
            if *key_epoch != state.key_epoch + 1 {
                return Err(AppError::bad_request("key epoch must be the next one"));
            }
        }
    }
    Ok(entry_hash(signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_protocol::teams::{TeamLogEntry, TeamMemberKeys, TEAM_LOG_FORMAT};
    use cc_protocol::Bytes;
    use ed25519_dalek::{Signer, SigningKey};

    struct Member {
        user: UserId,
        key: SigningKey,
    }

    fn member(seed: u8) -> Member {
        Member {
            user: UserId::new(),
            key: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    fn sign(m: &Member, entry: TeamLogEntry) -> SignedTeamLogEntry {
        let sig = m.key.sign(&team_log_message(&entry));
        SignedTeamLogEntry {
            entry,
            signature: Bytes::new(sig.to_bytes().to_vec()),
        }
    }

    fn entry(m: &Member, vault: VaultId, seq: u64, prev: [u8; 32], op: TeamLogOp) -> TeamLogEntry {
        TeamLogEntry {
            format: TEAM_LOG_FORMAT,
            vault_id: vault,
            seq,
            previous_hash: Bytes::new(prev.to_vec()),
            issued_at: 1_800_000_000,
            actor_user_id: m.user,
            actor_signing_key: Bytes::new(m.key.verifying_key().to_bytes().to_vec()),
            op,
        }
    }

    fn keys(m: &Member) -> TeamMemberKeys {
        TeamMemberKeys {
            user_id: m.user,
            encryption_key: Bytes::new(vec![4; 32]),
            signing_key: Bytes::new(m.key.verifying_key().to_bytes().to_vec()),
        }
    }

    #[test]
    fn genesis_then_append_rules() {
        let owner = member(1);
        let editor = member(2);
        let newbie = member(3);
        let vault = VaultId::new();
        let now = 1_800_000_000;
        let g = sign(
            &owner,
            entry(
                &owner,
                vault,
                0,
                [0; 32],
                TeamLogOp::Genesis {
                    owner: keys(&owner),
                },
            ),
        );
        let head = check_genesis(vault, owner.user, &g, now).unwrap();
        assert!(check_genesis(vault, editor.user, &g, now).is_err());

        let mut members = HashMap::new();
        members.insert(
            owner.user,
            LiveMember {
                role: VaultRole::Owner,
                signing_key: owner.key.verifying_key().to_bytes().to_vec(),
            },
        );
        members.insert(
            editor.user,
            LiveMember {
                role: VaultRole::Editor,
                signing_key: editor.key.verifying_key().to_bytes().to_vec(),
            },
        );
        let state = LogState {
            vault_id: vault,
            log_seq: 0,
            log_head: head,
            key_epoch: 0,
            members,
        };
        let add = TeamLogOp::AddMember {
            member: keys(&newbie),
            role: VaultRole::Viewer,
        };
        // Owner may add; an editor may not; wrong head conflicts; a forged
        // signature is refused.
        let ok = sign(&owner, entry(&owner, vault, 1, head, add.clone()));
        check_append(&state, owner.user, &ok, now).unwrap();
        let by_editor = sign(&editor, entry(&editor, vault, 1, head, add.clone()));
        assert!(check_append(&state, editor.user, &by_editor, now).is_err());
        let stale = sign(&owner, entry(&owner, vault, 1, [9; 32], add.clone()));
        assert_eq!(
            check_append(&state, owner.user, &stale, now)
                .unwrap_err()
                .code(),
            cc_protocol::ErrorCode::Conflict
        );
        let mut forged = ok.clone();
        forged.signature = Bytes::new(vec![1; 64]);
        assert!(check_append(&state, owner.user, &forged, now).is_err());
        // Signed by the owner but submitted by someone else.
        assert!(check_append(&state, editor.user, &ok, now).is_err());
        // The owner cannot be removed or leave.
        let rm = sign(
            &owner,
            entry(
                &owner,
                vault,
                1,
                head,
                TeamLogOp::RemoveMember {
                    user_id: owner.user,
                },
            ),
        );
        assert!(check_append(&state, owner.user, &rm, now).is_err());
        let leave = sign(&owner, entry(&owner, vault, 1, head, TeamLogOp::Leave));
        assert!(check_append(&state, owner.user, &leave, now).is_err());
        let leave = sign(&editor, entry(&editor, vault, 1, head, TeamLogOp::Leave));
        check_append(&state, editor.user, &leave, now).unwrap();
        // Rotation must be the next epoch.
        let rot = sign(
            &owner,
            entry(
                &owner,
                vault,
                1,
                head,
                TeamLogOp::RotateKey { key_epoch: 2 },
            ),
        );
        assert!(check_append(&state, owner.user, &rot, now).is_err());
        // Far-off timestamps are refused.
        assert!(check_append(&state, owner.user, &ok, now + 3 * 24 * 3600).is_err());
    }
}
