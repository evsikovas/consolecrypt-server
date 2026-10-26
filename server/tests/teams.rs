// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Teams (protocol 1.9): create, invite, accept, add with a signed log
//! entry, roles in sync, removal, key rotation, and the rules the server
//! enforces on the membership log.

mod common;

use consolecrypt_server::mail::MailKind;

use cc_protocol::envelopes::{
    EnvelopeAlgorithm, EnvelopeKind, EnvelopeMetadata, NewEnvelope, RecipientType,
};
use cc_protocol::teams::{
    team_log_hash_input, team_log_message, SignedTeamLogEntry, TeamKeyChainLink, TeamLogEntry,
    TeamLogOp, TeamMemberKeys, TEAM_LOG_FORMAT,
};
use cc_protocol::vaults::VaultRole;
use cc_protocol::{paths, Bytes, ObjectId, UserId, VaultId};
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// A member's per-team identity.
struct TeamKey {
    user: UserId,
    signing: SigningKey,
    encryption: [u8; 32],
}

impl TeamKey {
    fn new(user: UserId) -> Self {
        Self {
            user,
            signing: SigningKey::from_bytes(&random::<32>()),
            encryption: random::<32>(),
        }
    }

    fn keys(&self) -> TeamMemberKeys {
        TeamMemberKeys {
            user_id: self.user,
            encryption_key: Bytes::new(self.encryption.to_vec()),
            signing_key: Bytes::new(self.signing.verifying_key().to_bytes().to_vec()),
        }
    }

    fn sign(&self, vault: VaultId, seq: u64, prev: &[u8; 32], op: TeamLogOp) -> SignedTeamLogEntry {
        let entry = TeamLogEntry {
            format: TEAM_LOG_FORMAT,
            vault_id: vault,
            seq,
            previous_hash: Bytes::new(prev.to_vec()),
            issued_at: chrono::Utc::now().timestamp(),
            actor_user_id: self.user,
            actor_signing_key: Bytes::new(self.signing.verifying_key().to_bytes().to_vec()),
            op,
        };
        let signature = self.signing.sign(&team_log_message(&entry));
        SignedTeamLogEntry {
            entry,
            signature: Bytes::new(signature.to_bytes().to_vec()),
        }
    }
}

fn hash(e: &SignedTeamLogEntry) -> [u8; 32] {
    Sha256::digest(team_log_hash_input(e)).into()
}

fn user_envelope(user: UserId) -> NewEnvelope {
    NewEnvelope {
        recipient_type: RecipientType::User,
        recipient_id: Some(user.into()),
        kind: EnvelopeKind::VrkV1,
        metadata: EnvelopeMetadata {
            algorithm: EnvelopeAlgorithm::X25519HkdfSha256Xchacha20poly1305V1,
            kdf: None,
            ephemeral_public_key: Some(Bytes::new(random::<32>().to_vec())),
        },
        ciphertext: Bytes::new(random::<48>().to_vec()),
        nonce: Bytes::new(random::<24>().to_vec()),
    }
}

fn team_path(template: &str, vault: VaultId) -> String {
    paths::fill(template, &[("vault_id", &vault.to_string())])
}

/// Mark `s`'s address as verified (invitations go only to such accounts).
async fn verified(srv: &TestServer, s: Session) -> Session {
    sqlx::query("UPDATE users SET email_verified_at = now() WHERE id = $1")
        .bind(uuid::Uuid::from(s.user_id))
        .execute(&srv.state.db)
        .await
        .unwrap();
    s
}

#[tokio::test]
async fn team_lifecycle() {
    let Some(srv) = TestServer::spawn(|_| {}).await else {
        return;
    };
    let a = srv.new_account().await;
    let b = verified(&srv, srv.new_account().await).await;
    let c = verified(&srv, srv.new_account().await).await;
    let ka = TeamKey::new(a.user_id);
    let kb = TeamKey::new(b.user_id);
    let team = TestVault::new();

    // ── create ──────────────────────────────────────────────────────────
    let genesis = ka.sign(
        team.id,
        0,
        &[0; 32],
        TeamLogOp::Genesis { owner: ka.keys() },
    );
    let create = json!({
        "vault_id": team.id,
        "vault_access_key": team.vak_bytes(),
        "genesis": genesis,
        "owner_envelope": user_envelope(a.user_id),
        "device_envelope": device_envelope(a.device.id),
    });
    let (st, info) = srv.post(paths::TEAMS, Some(&a.access), &create).await;
    assert_eq!(st, StatusCode::CREATED, "{info}");
    assert_eq!(info["role"], "owner");
    assert_eq!(info["members_count"], 1);
    assert_eq!(info["caller_trusted"], true);
    let mut head = hash(&genesis);
    // A genesis signed for another user is refused.
    let other = TestVault::new();
    let forged = kb.sign(
        other.id,
        0,
        &[0; 32],
        TeamLogOp::Genesis { owner: kb.keys() },
    );
    let (st, _) = srv
        .post(
            paths::TEAMS,
            Some(&a.access),
            &json!({
                "vault_id": other.id,
                "vault_access_key": other.vak_bytes(),
                "genesis": forged,
                "owner_envelope": user_envelope(a.user_id),
                "device_envelope": device_envelope(a.device.id),
            }),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Teams are not personal vaults.
    let (_, vaults) = srv.get(paths::VAULTS, &a.access).await;
    assert!(vaults["vaults"].as_array().unwrap().is_empty(), "{vaults}");
    let (_, teams) = srv.get(paths::TEAMS, &a.access).await;
    assert_eq!(teams["teams"].as_array().unwrap().len(), 1);

    // The owner pushes into the team.
    let obj = ObjectId::new();
    let (st, body) = srv.push(&a, team.id, vec![put(obj, 0)]).await;
    assert_eq!(st, StatusCode::OK, "{body}");

    // ── invite / accept ─────────────────────────────────────────────────
    let invitations = team_path(paths::TEAM_INVITATIONS, team.id);
    let (st, _) = srv
        .post(
            &invitations,
            Some(&a.access),
            &json!({"email": b.email, "role": "editor", "note": "Ops"}),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    // Unknown address: same answer, nothing created.
    let (st, _) = srv
        .post(
            &invitations,
            Some(&a.access),
            &json!({"email": "nobody@example.invalid", "role": "viewer"}),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    // One invitation mail, to the existing account only.
    srv.mailer.wait_for(MailKind::TeamInvitation, 1).await;
    {
        let mails = srv.mailer.messages.lock().unwrap();
        let invites: Vec<_> = mails
            .iter()
            .filter(|(k, _, _)| *k == MailKind::TeamInvitation)
            .collect();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0].1, b.email.to_lowercase());
        assert!(invites[0].2.contains("Ops") && invites[0].2.contains("editor"));
    }
    // Non-members cannot invite.
    let (st, _) = srv
        .post(
            &invitations,
            Some(&c.access),
            &json!({"email": c.email, "role": "viewer"}),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (_, inbox) = srv.get(paths::TEAM_INVITATIONS_INBOX, &b.access).await;
    let inv = &inbox["invitations"][0];
    assert_eq!(inv["note"], "Ops");
    assert_eq!(inv["inviter_email"], a.email.to_lowercase());
    assert_eq!(
        inv["inviter_signing_key"],
        json!(Bytes::new(ka.signing.verifying_key().to_bytes().to_vec()))
    );
    let inv_id = inv["invitation_id"].as_str().unwrap().to_owned();
    let accept = paths::fill(paths::TEAM_INVITATION_ACCEPT, &[("invitation_id", &inv_id)]);
    let kb_keys = kb.keys();
    let (st, accepted) = srv
        .post(
            &accept,
            Some(&b.access),
            &json!({"encryption_key": kb_keys.encryption_key, "signing_key": kb_keys.signing_key}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{accepted}");
    assert_eq!(accepted["status"], "accepted");
    let (_, pending) = srv.get(&invitations, &a.access).await;
    assert_eq!(
        pending["invitations"][0]["member_keys"]["user_id"],
        json!(b.user_id)
    );

    // ── add member with a signed entry ──────────────────────────────────
    let log = team_path(paths::TEAM_LOG, team.id);
    let add = ka.sign(
        team.id,
        1,
        &head,
        TeamLogOp::AddMember {
            member: kb.keys(),
            role: VaultRole::Editor,
        },
    );
    // Wrong VAK.
    let (st, _) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": add, "vault_access_key": Bytes::new(vec![1; 32]),
                    "invitation_id": inv_id, "envelopes": [user_envelope(b.user_id)]}),
        )
        .await;
    assert_ne!(st, StatusCode::OK, "wrong vault access key");
    // Keys that differ from the accepted invitation.
    let other_keys = TeamKey::new(b.user_id);
    let mismatched = ka.sign(
        team.id,
        1,
        &head,
        TeamLogOp::AddMember {
            member: other_keys.keys(),
            role: VaultRole::Editor,
        },
    );
    let (st, _) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": mismatched, "vault_access_key": team.vak_bytes(),
                    "invitation_id": inv_id, "envelopes": [user_envelope(b.user_id)]}),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, res) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": add, "vault_access_key": team.vak_bytes(),
                    "invitation_id": inv_id, "envelopes": [user_envelope(b.user_id)]}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{res}");
    assert_eq!(res["members"].as_array().unwrap().len(), 2);
    head = hash(&add);
    // Replaying the same entry conflicts (head moved).
    let (st, _) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": add, "vault_access_key": team.vak_bytes(),
                    "invitation_id": inv_id, "envelopes": [user_envelope(b.user_id)]}),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);

    // ── the member ──────────────────────────────────────────────────────
    let (_, t) = srv.get(&team_path(paths::TEAM, team.id), &b.access).await;
    assert_eq!(t["team"]["role"], "editor");
    let (st, key) = srv
        .get(&team_path(paths::TEAM_KEY, team.id), &b.access)
        .await;
    assert_eq!(st, StatusCode::OK, "{key}");
    assert_eq!(key["key_epoch"], 0);
    assert_eq!(key["envelope"]["recipient_type"], "user");
    let (_, entries) = srv.get(&log, &b.access).await;
    assert_eq!(entries["entries"].as_array().unwrap().len(), 2);
    // Device trust via VAK, then sync.
    let (st, body) = srv.attest(&b, &team).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let (st, _) = srv.push(&b, team.id, vec![put(ObjectId::new(), 0)]).await;
    assert_eq!(st, StatusCode::OK);
    let (st, changes) = srv.changes(&b, team.id, 0).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(changes["changes"].as_array().unwrap().len(), 2);

    // ── roles ───────────────────────────────────────────────────────────
    let demote = ka.sign(
        team.id,
        2,
        &head,
        TeamLogOp::ChangeRole {
            user_id: b.user_id,
            role: VaultRole::Viewer,
        },
    );
    let (st, _) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": demote, "vault_access_key": team.vak_bytes()}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    head = hash(&demote);
    let (st, body) = srv.push(&b, team.id, vec![put(ObjectId::new(), 0)]).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(body["details"]["reason"], "team_role");
    // A viewer cannot sign membership changes.
    let by_viewer = kb.sign(
        team.id,
        3,
        &head,
        TeamLogOp::RemoveMember { user_id: a.user_id },
    );
    let (st, _) = srv
        .post(
            &log,
            Some(&b.access),
            &json!({"entry": by_viewer, "vault_access_key": team.vak_bytes()}),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // ── remove + rotate ─────────────────────────────────────────────────
    let remove = ka.sign(
        team.id,
        3,
        &head,
        TeamLogOp::RemoveMember { user_id: b.user_id },
    );
    let (st, res) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": remove, "vault_access_key": team.vak_bytes()}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{res}");
    head = hash(&remove);
    assert_eq!(res["team"]["rotation_required"], true);
    let (st, _) = srv.get(&team_path(paths::TEAM, team.id), &b.access).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = srv
        .get(&team_path(paths::TEAM_KEY, team.id), &b.access)
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = srv.changes(&b, team.id, 0).await;
    assert_ne!(st, StatusCode::OK, "removed member cannot pull");

    let new_vak = random::<32>();
    let rotate = ka.sign(team.id, 4, &head, TeamLogOp::RotateKey { key_epoch: 1 });
    let link = TeamKeyChainLink {
        key_epoch: 1,
        nonce: Bytes::new(random::<24>().to_vec()),
        ciphertext: Bytes::new(random::<48>().to_vec()),
    };
    // Envelopes must cover exactly the remaining members.
    let (st, _) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": rotate, "vault_access_key": team.vak_bytes(),
                    "new_vault_access_key": Bytes::new(new_vak.to_vec()), "chain_link": link,
                    "envelopes": [user_envelope(a.user_id), user_envelope(b.user_id)]}),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, res) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": rotate, "vault_access_key": team.vak_bytes(),
                    "new_vault_access_key": Bytes::new(new_vak.to_vec()), "chain_link": link,
                    "envelopes": [user_envelope(a.user_id)]}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{res}");
    assert_eq!(res["team"]["key_epoch"], 1);
    assert_eq!(res["team"]["rotation_required"], false);
    let (_, key) = srv
        .get(&team_path(paths::TEAM_KEY, team.id), &a.access)
        .await;
    assert_eq!(key["key_epoch"], 1);
    assert_eq!(key["chain"][0]["key_epoch"], 1);
    // The old VAK no longer authorizes log appends.
    head = hash(&rotate);
    let leave_probe = ka.sign(team.id, 5, &head, TeamLogOp::Leave);
    let (st, _) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": leave_probe, "vault_access_key": team.vak_bytes()}),
        )
        .await;
    assert_ne!(st, StatusCode::OK);
    let (st, body) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": leave_probe, "vault_access_key": Bytes::new(new_vak.to_vec())}),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "the owner cannot leave: {body}");
    let _: Value = body;
}

/// Security review SEC-04: in a Team Vault every member holds T(V) + K(V),
/// so the generic envelope routes must not let one member delete or replace
/// another member's envelopes, nor plant a password/recovery envelope.
#[tokio::test]
async fn team_envelopes_are_self_service_only() {
    let Some(srv) = TestServer::spawn(|_| {}).await else {
        return;
    };
    let a = srv.new_account().await;
    let b = verified(&srv, srv.new_account().await).await;
    let ka = TeamKey::new(a.user_id);
    let kb = TeamKey::new(b.user_id);
    let team = TestVault::new();

    let genesis = ka.sign(
        team.id,
        0,
        &[0; 32],
        TeamLogOp::Genesis { owner: ka.keys() },
    );
    let (st, info) = srv
        .post(
            paths::TEAMS,
            Some(&a.access),
            &json!({
                "vault_id": team.id,
                "vault_access_key": team.vak_bytes(),
                "genesis": genesis,
                "owner_envelope": user_envelope(a.user_id),
                "device_envelope": device_envelope(a.device.id),
            }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{info}");
    let head = hash(&genesis);

    // b joins as a viewer and trusts a device.
    let invitations = team_path(paths::TEAM_INVITATIONS, team.id);
    let (st, _) = srv
        .post(
            &invitations,
            Some(&a.access),
            &json!({"email": b.email, "role": "viewer"}),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (_, inbox) = srv.get(paths::TEAM_INVITATIONS_INBOX, &b.access).await;
    let inv_id = inbox["invitations"][0]["invitation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let accept = paths::fill(paths::TEAM_INVITATION_ACCEPT, &[("invitation_id", &inv_id)]);
    let kb_keys = kb.keys();
    let (st, _) = srv
        .post(
            &accept,
            Some(&b.access),
            &json!({"encryption_key": kb_keys.encryption_key, "signing_key": kb_keys.signing_key}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let add = ka.sign(
        team.id,
        1,
        &head,
        TeamLogOp::AddMember {
            member: kb.keys(),
            role: VaultRole::Viewer,
        },
    );
    let (st, res) = srv
        .post(
            &team_path(paths::TEAM_LOG, team.id),
            Some(&a.access),
            &json!({"entry": add, "vault_access_key": team.vak_bytes(),
                    "invitation_id": inv_id, "envelopes": [user_envelope(b.user_id)]}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{res}");
    let (st, body) = srv.attest(&b, &team).await;
    assert_eq!(st, StatusCode::OK, "{body}");

    let envelopes_path = team_path(paths::VAULT_ENVELOPES, team.id);
    let (st, list) = srv.get(&envelopes_path, &b.access).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    let find = |list: &Value, kind: &str, id: String| {
        list["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["recipient_type"] == kind && e["recipient_id"] == json!(id))
            .map(|e| e["envelope_id"].as_str().unwrap().to_owned())
    };
    let owner_user = find(&list, "user", a.user_id.to_string()).expect("owner user envelope");
    let owner_device =
        find(&list, "device", a.device.id.to_string()).expect("owner device envelope");
    let vak = json!({"vault_access_key": team.vak_bytes()});
    let envelope_path = |id: &str| {
        paths::fill(
            paths::VAULT_ENVELOPE,
            &[("vault_id", &team.id.to_string()), ("envelope_id", id)],
        )
    };

    // The viewer cannot cut the owner off …
    for id in [&owner_user, &owner_device] {
        let (st, body) = srv.delete(&envelope_path(id), &b.access, Some(&vak)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    }
    // … nor plant a key for the owner …
    let (st, body) = srv
        .post(
            &envelopes_path,
            Some(&b.access),
            &json!({"vault_access_key": team.vak_bytes(), "envelope": user_envelope(a.user_id)}),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    // … nor add a password or recovery envelope to the team.
    for (path, envelope) in [
        (paths::RECOVERY_VAULT_PASSWORD_REPLACE, password_envelope()),
        (paths::RECOVERY_VAULT_RECOVERY_REPLACE, recovery_envelope()),
    ] {
        let (st, body) = srv
            .post(
                path,
                Some(&b.access),
                &json!({"vault_id": team.id, "vault_access_key": team.vak_bytes(),
                        "envelope": envelope}),
            )
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{path}: {body}");
    }
    // The owner's envelopes are intact.
    let (_, after) = srv.get(&envelopes_path, &a.access).await;
    assert!(
        find(&after, "user", a.user_id.to_string()).is_some(),
        "{after}"
    );
    assert!(
        find(&after, "device", a.device.id.to_string()).is_some(),
        "{after}"
    );

    // A member still manages their own envelopes.
    let (st, body) = srv
        .post(
            &envelopes_path,
            Some(&b.access),
            &json!({"vault_access_key": team.vak_bytes(), "envelope": user_envelope(b.user_id)}),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let own_device = find(&after, "device", b.device.id.to_string()).expect("own device envelope");
    let (st, body) = srv
        .delete(&envelope_path(&own_device), &b.access, Some(&vak))
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{body}");
}

/// Invite `who` as `role`, let them accept, and submit the `AddMember` entry
/// signed by `signer`. Returns the log status and advances `head`/`seq` on
/// success.
#[allow(clippy::too_many_arguments)]
async fn add_member(
    srv: &TestServer,
    team: &TestVault,
    inviter: &Session,
    signer: (&Session, &TeamKey),
    who: (&Session, &TeamKey),
    role: VaultRole,
    head: &mut [u8; 32],
    seq: &mut u64,
) -> StatusCode {
    let (st, body) = srv
        .post(
            &team_path(paths::TEAM_INVITATIONS, team.id),
            Some(&inviter.access),
            &json!({"email": who.0.email, "role": role}),
        )
        .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{body}");
    let (_, inbox) = srv.get(paths::TEAM_INVITATIONS_INBOX, &who.0.access).await;
    let inv_id = inbox["invitations"][0]["invitation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let keys = who.1.keys();
    let (st, _) = srv
        .post(
            &paths::fill(paths::TEAM_INVITATION_ACCEPT, &[("invitation_id", &inv_id)]),
            Some(&who.0.access),
            &json!({"encryption_key": keys.encryption_key, "signing_key": keys.signing_key}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let add = signer.1.sign(
        team.id,
        *seq + 1,
        head,
        TeamLogOp::AddMember { member: keys, role },
    );
    let (st, _) = srv
        .post(
            &team_path(paths::TEAM_LOG, team.id),
            Some(&signer.0.access),
            &json!({"entry": add, "vault_access_key": team.vak_bytes(),
                    "invitation_id": inv_id, "envelopes": [user_envelope(who.0.user_id)]}),
        )
        .await;
    if st == StatusCode::OK {
        *head = hash(&add);
        *seq += 1;
    }
    st
}

/// Security review SEC-09 and SEC-10: only the owner appoints admins (as
/// every client's log check requires — an entry they all refuse would stop
/// the team), and invitations go only to accounts with a verified address.
#[tokio::test]
async fn admins_come_only_from_the_owner_and_invitees_are_verified() {
    let Some(srv) = TestServer::spawn(|_| {}).await else {
        return;
    };
    let a = srv.new_account().await;
    let b = verified(&srv, srv.new_account().await).await;
    let c = verified(&srv, srv.new_account().await).await;
    let d = verified(&srv, srv.new_account().await).await;
    let (ka, kb, kc, kd) = (
        TeamKey::new(a.user_id),
        TeamKey::new(b.user_id),
        TeamKey::new(c.user_id),
        TeamKey::new(d.user_id),
    );
    let team = TestVault::new();
    let genesis = ka.sign(
        team.id,
        0,
        &[0; 32],
        TeamLogOp::Genesis { owner: ka.keys() },
    );
    let (st, info) = srv
        .post(
            paths::TEAMS,
            Some(&a.access),
            &json!({
                "vault_id": team.id,
                "vault_access_key": team.vak_bytes(),
                "genesis": genesis,
                "owner_envelope": user_envelope(a.user_id),
                "device_envelope": device_envelope(a.device.id),
            }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{info}");
    let mut head = hash(&genesis);
    let mut seq = 0;
    let owner = (&a, &ka);
    // The owner adds an admin and an editor.
    let st = add_member(
        &srv,
        &team,
        &a,
        owner,
        (&b, &kb),
        VaultRole::Admin,
        &mut head,
        &mut seq,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let st = add_member(
        &srv,
        &team,
        &a,
        owner,
        (&c, &kc),
        VaultRole::Editor,
        &mut head,
        &mut seq,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // SEC-09: the admin cannot promote the editor to admin …
    let log = team_path(paths::TEAM_LOG, team.id);
    let promote = kb.sign(
        team.id,
        seq + 1,
        &head,
        TeamLogOp::ChangeRole {
            user_id: c.user_id,
            role: VaultRole::Admin,
        },
    );
    let (st, body) = srv
        .post(
            &log,
            Some(&b.access),
            &json!({"entry": promote, "vault_access_key": team.vak_bytes()}),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    // … nor add an admin, even with the owner's admin invitation.
    let st = add_member(
        &srv,
        &team,
        &a,
        (&b, &kb),
        (&d, &kd),
        VaultRole::Admin,
        &mut head,
        &mut seq,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // The owner still can.
    let promote = ka.sign(
        team.id,
        seq + 1,
        &head,
        TeamLogOp::ChangeRole {
            user_id: c.user_id,
            role: VaultRole::Admin,
        },
    );
    let (st, body) = srv
        .post(
            &log,
            Some(&a.access),
            &json!({"entry": promote, "vault_access_key": team.vak_bytes()}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");

    // SEC-10: an account that never verified its address gets no invitation.
    let unverified = srv.new_account().await;
    let before = srv.mailer.messages.lock().unwrap().len();
    let (st, _) = srv
        .post(
            &team_path(paths::TEAM_INVITATIONS, team.id),
            Some(&a.access),
            &json!({"email": unverified.email, "role": "viewer"}),
        )
        .await;
    assert_eq!(
        st,
        StatusCode::ACCEPTED,
        "same answer as an unknown address"
    );
    let (_, inbox) = srv
        .get(paths::TEAM_INVITATIONS_INBOX, &unverified.access)
        .await;
    assert!(
        inbox["invitations"].as_array().unwrap().is_empty(),
        "{inbox}"
    );
    assert_eq!(
        srv.mailer.messages.lock().unwrap().len(),
        before,
        "no invitation mail"
    );
}

/// Protocol 1.12 (security review SEC-03b): signed team key commitments are
/// checked (epoch, signer, signature), stored per epoch, served with the
/// key, and only owners or admins may publish one.
#[tokio::test]
async fn team_key_commitments_are_checked_and_served() {
    use cc_protocol::teams::{team_key_commitment_message, TeamKeyCommitment};
    let Some(srv) = TestServer::spawn(|_| {}).await else {
        return;
    };
    let a = srv.new_account().await;
    let b = verified(&srv, srv.new_account().await).await;
    let (ka, kb) = (TeamKey::new(a.user_id), TeamKey::new(b.user_id));
    let team = TestVault::new();
    let commit = |k: &TeamKey, epoch: u32, value: [u8; 32]| TeamKeyCommitment {
        key_epoch: epoch,
        commitment: Bytes::new(value.to_vec()),
        signer_user_id: k.user,
        signature: Bytes::new(
            k.signing
                .sign(&team_key_commitment_message(team.id, epoch, &value, k.user))
                .to_bytes()
                .to_vec(),
        ),
    };
    let genesis = ka.sign(
        team.id,
        0,
        &[0; 32],
        TeamLogOp::Genesis { owner: ka.keys() },
    );
    let create = |kc: TeamKeyCommitment| {
        json!({
            "vault_id": team.id,
            "vault_access_key": team.vak_bytes(),
            "genesis": genesis,
            "owner_envelope": user_envelope(a.user_id),
            "device_envelope": device_envelope(a.device.id),
            "key_commitment": kc,
        })
    };
    // A commitment signed by someone else is refused, and nothing is created.
    let (st, _) = srv
        .post(
            paths::TEAMS,
            Some(&a.access),
            &create(commit(&kb, 0, [1; 32])),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let mut forged = commit(&ka, 0, [1; 32]);
    forged.commitment = Bytes::new(vec![2; 32]);
    let (st, _) = srv
        .post(paths::TEAMS, Some(&a.access), &create(forged))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, info) = srv
        .post(
            paths::TEAMS,
            Some(&a.access),
            &create(commit(&ka, 0, [1; 32])),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{info}");
    let (_, key) = srv
        .get(&team_path(paths::TEAM_KEY, team.id), &a.access)
        .await;
    assert_eq!(key["key_commitment"]["key_epoch"], 0);
    assert_eq!(
        key["key_commitment"]["commitment"],
        json!(Bytes::new(vec![1; 32]))
    );

    // A viewer cannot publish one; the owner can replace it.
    let mut head = hash(&genesis);
    let mut seq = 0;
    let st = add_member(
        &srv,
        &team,
        &a,
        (&a, &ka),
        (&b, &kb),
        VaultRole::Viewer,
        &mut head,
        &mut seq,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let put = team_path(paths::TEAM_KEY_COMMITMENT, team.id);
    let (st, _) = srv
        .request(
            reqwest::Method::PUT,
            &put,
            Some(&b.access),
            Some(&json!({"vault_access_key": team.vak_bytes(), "key_commitment": commit(&kb, 0, [3; 32])})),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = srv
        .request(
            reqwest::Method::PUT,
            &put,
            Some(&a.access),
            Some(&json!({"vault_access_key": team.vak_bytes(), "key_commitment": commit(&ka, 1, [3; 32])})),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "not the current epoch");
    let (st, body) = srv
        .request(
            reqwest::Method::PUT,
            &put,
            Some(&a.access),
            Some(&json!({"vault_access_key": team.vak_bytes(), "key_commitment": commit(&ka, 0, [3; 32])})),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{body}");
    let (_, key) = srv
        .get(&team_path(paths::TEAM_KEY, team.id), &b.access)
        .await;
    assert_eq!(
        key["key_commitment"]["commitment"],
        json!(Bytes::new(vec![3; 32]))
    );

    // A rotation carries the new epoch's commitment.
    let new_vak = random::<32>();
    let rotate = ka.sign(
        team.id,
        seq + 1,
        &head,
        TeamLogOp::RotateKey { key_epoch: 1 },
    );
    let link = TeamKeyChainLink {
        key_epoch: 1,
        nonce: Bytes::new(random::<24>().to_vec()),
        ciphertext: Bytes::new(random::<48>().to_vec()),
    };
    let (st, res) = srv
        .post(
            &team_path(paths::TEAM_LOG, team.id),
            Some(&a.access),
            &json!({"entry": rotate, "vault_access_key": team.vak_bytes(),
                    "new_vault_access_key": Bytes::new(new_vak.to_vec()), "chain_link": link,
                    "envelopes": [user_envelope(a.user_id), user_envelope(b.user_id)],
                    "key_commitment": commit(&ka, 1, [4; 32])}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{res}");
    let (_, key) = srv
        .get(&team_path(paths::TEAM_KEY, team.id), &b.access)
        .await;
    assert_eq!(key["key_epoch"], 1);
    assert_eq!(key["key_commitment"]["key_epoch"], 1);
    assert_eq!(
        key["key_commitment"]["commitment"],
        json!(Bytes::new(vec![4; 32]))
    );
}
