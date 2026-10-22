//! Notes attached to a shared object (`share_notes_v1`).
//!
//! The owner device issues a random 32-byte notes key per access epoch and
//! wraps it to every member device like a revision DEK; the key set is signed
//! by the owner device so the server cannot substitute its own key. Each note
//! is encrypted with a key derived from the epoch's notes key and signed by its
//! author device over the hash of the plaintext payload (which carries a random
//! salt). The signature does not cover the epoch, so the owner can re-encrypt
//! notes into a new epoch without touching authorship.

use crate::sharing::{SharedKeyEnvelope, SharingMember, SharingValidationError, MAX_MEMBERS};
use crate::{Bytes, DeviceId, ObjectId, ShareId, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const CAPABILITY: &str = "share_notes_v1";
pub const FORMAT: u16 = 1;
pub const MAX_NOTES_PER_SHARE: usize = 500;
/// A 256 KiB note body plus JSON framing, padding and the AEAD tag.
pub const MAX_NOTE_CIPHERTEXT_BYTES: usize = 288 * 1024 + 16;
/// Notes re-encrypted per rekey request.
pub const MAX_REKEY_BATCH: usize = 100;

pub mod labels {
    pub const KEY_SET: &[u8] = b"consolecrypt/sharing/v1/notes-key-set\0";
    pub const ENVELOPE_AAD: &[u8] = b"consolecrypt/sharing/v1/notes-envelope-aad\0";
    pub const ENVELOPE_KEY: &[u8] = b"consolecrypt/sharing/v1/notes-envelope-key\0";
    pub const NOTE_KEY: &[u8] = b"consolecrypt/sharing/v1/note-key\0";
    pub const NOTE_AAD: &[u8] = b"consolecrypt/sharing/v1/note-aad\0";
    pub const NOTE: &[u8] = b"consolecrypt/sharing/v1/note\0";
}

pub fn notes_path(share_id: ShareId) -> String {
    format!("{}/{share_id}/notes", crate::sharing::API_PATH)
}

/// The notes key of one access epoch, wrapped to every member device and
/// signed by the owner device of the share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNotesKeySet {
    pub format: u16,
    pub server_instance_id: Uuid,
    pub share_id: ShareId,
    pub access_epoch: u64,
    /// SHA-256 of the canonical access manifest of this epoch.
    pub manifest_hash: Bytes,
    pub owner_device_id: DeviceId,
    pub envelopes: Vec<SharedKeyEnvelope>,
    pub signature: Bytes,
}

/// One encrypted note. `payload_hash` is SHA-256 of the padded plaintext
/// payload; readers recompute it after decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNote {
    pub note_id: ObjectId,
    pub author_user_id: UserId,
    pub author_device_id: DeviceId,
    pub revision: u64,
    pub access_epoch: u64,
    pub nonce: Bytes,
    pub ciphertext: Bytes,
    pub payload_hash: Bytes,
    pub signature: Bytes,
}

/// A note moved into the current epoch by the owner device: authorship,
/// revision, payload hash and signature stay as they were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyedSharedNote {
    pub note_id: ObjectId,
    pub revision: u64,
    pub nonce: Bytes,
    pub ciphertext: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeySharedNotesRequest {
    pub access_epoch: u64,
    pub notes: Vec<RekeyedSharedNote>,
}

/// Every note of a share and the key sets of the epochs they are in. The
/// current epoch's key set is included when it exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNotesPage {
    pub access_epoch: u64,
    pub key_sets: Vec<SharedNotesKeySet>,
    pub notes: Vec<SharedNote>,
}

fn require(condition: bool, field: &'static str) -> Result<(), SharingValidationError> {
    if condition {
        Ok(())
    } else {
        Err(SharingValidationError(field))
    }
}

fn epoch(value: u64) -> Result<(), SharingValidationError> {
    require(value > 0 && value <= i64::MAX as u64, "access_epoch")
}

pub fn validate_key_set(k: &SharedNotesKeySet) -> Result<(), SharingValidationError> {
    require(k.format == FORMAT, "format")?;
    require(!k.server_instance_id.is_nil(), "server_instance_id")?;
    require(k.share_id != ShareId::NIL, "share_id")?;
    epoch(k.access_epoch)?;
    require(k.manifest_hash.len() == 32, "manifest_hash")?;
    require(k.owner_device_id != DeviceId::NIL, "owner_device_id")?;
    require(k.signature.len() == 64, "signature")?;
    require((1..=MAX_MEMBERS).contains(&k.envelopes.len()), "envelopes")?;
    let mut seen = BTreeSet::new();
    for e in &k.envelopes {
        require(
            e.recipient_device_id != DeviceId::NIL,
            "recipient_device_id",
        )?;
        require(seen.insert(e.recipient_device_id), "duplicate_envelope")?;
        require(e.ephemeral_public_key.len() == 32, "ephemeral_public_key")?;
        require(e.nonce.len() == 24 && e.ciphertext.len() == 48, "envelope")?;
    }
    Ok(())
}

pub fn validate_note(n: &SharedNote) -> Result<(), SharingValidationError> {
    require(n.note_id != ObjectId::NIL, "note_id")?;
    require(
        n.author_user_id != UserId::NIL && n.author_device_id != DeviceId::NIL,
        "author",
    )?;
    require(n.revision > 0 && n.revision <= i64::MAX as u64, "revision")?;
    epoch(n.access_epoch)?;
    require(n.nonce.len() == 24, "nonce")?;
    require(
        (16..=MAX_NOTE_CIPHERTEXT_BYTES).contains(&n.ciphertext.len()),
        "ciphertext",
    )?;
    require(n.payload_hash.len() == 32, "payload_hash")?;
    require(n.signature.len() == 64, "signature")
}

pub fn validate_rekey(r: &RekeySharedNotesRequest) -> Result<(), SharingValidationError> {
    epoch(r.access_epoch)?;
    require((1..=MAX_REKEY_BATCH).contains(&r.notes.len()), "notes")?;
    let mut seen = BTreeSet::new();
    for n in &r.notes {
        require(
            n.note_id != ObjectId::NIL && seen.insert(n.note_id),
            "note_id",
        )?;
        require(n.revision > 0 && n.revision <= i64::MAX as u64, "revision")?;
        require(n.nonce.len() == 24, "nonce")?;
        require(
            (16..=MAX_NOTE_CIPHERTEXT_BYTES).contains(&n.ciphertext.len()),
            "ciphertext",
        )?;
    }
    Ok(())
}

/// What the owner device signs: everything in the key set but the signature.
pub fn notes_key_set_message(k: &SharedNotesKeySet) -> Result<Vec<u8>, SharingValidationError> {
    validate_key_set(k)?;
    let mut out = labels::KEY_SET.to_vec();
    out.extend_from_slice(&k.format.to_be_bytes());
    out.extend_from_slice(k.server_instance_id.as_bytes());
    out.extend_from_slice(k.share_id.as_bytes());
    out.extend_from_slice(&k.access_epoch.to_be_bytes());
    out.extend_from_slice(k.manifest_hash.as_slice());
    out.extend_from_slice(k.owner_device_id.as_bytes());
    out.extend_from_slice(&(k.envelopes.len() as u32).to_be_bytes());
    let mut envelopes: Vec<_> = k.envelopes.iter().collect();
    envelopes.sort_by_key(|e| e.recipient_device_id);
    for e in envelopes {
        out.extend_from_slice(e.recipient_device_id.as_bytes());
        out.extend_from_slice(e.ephemeral_public_key.as_slice());
        out.extend_from_slice(e.nonce.as_slice());
        out.extend_from_slice(e.ciphertext.as_slice());
    }
    Ok(out)
}

/// AAD of the notes-key envelope for one member device.
pub fn notes_envelope_aad(
    server_instance_id: Uuid,
    share_id: ShareId,
    access_epoch: u64,
    member: &SharingMember,
    ephemeral: &[u8; 32],
) -> Result<Vec<u8>, SharingValidationError> {
    require(!server_instance_id.is_nil(), "server_instance_id")?;
    require(share_id != ShareId::NIL, "share_id")?;
    epoch(access_epoch)?;
    crate::sharing::validate_member(member)?;
    let mut out = labels::ENVELOPE_AAD.to_vec();
    out.extend_from_slice(&FORMAT.to_be_bytes());
    out.extend_from_slice(server_instance_id.as_bytes());
    out.extend_from_slice(share_id.as_bytes());
    out.extend_from_slice(&access_epoch.to_be_bytes());
    out.extend_from_slice(member.user_id.as_bytes());
    out.extend_from_slice(member.device_id.as_bytes());
    out.extend_from_slice(member.encryption_public_key.as_slice());
    out.extend_from_slice(member.signing_public_key.as_slice());
    out.extend_from_slice(ephemeral);
    Ok(out)
}

/// HKDF `info` for one note's content key under an epoch's notes key (the
/// note id is the salt).
pub fn note_key_info(access_epoch: u64) -> Vec<u8> {
    let mut out = labels::NOTE_KEY.to_vec();
    out.extend_from_slice(&access_epoch.to_be_bytes());
    out
}

/// AEAD associated data of one note ciphertext.
pub fn note_aad(
    server_instance_id: Uuid,
    share_id: ShareId,
    note_id: ObjectId,
    access_epoch: u64,
    revision: u64,
    author_device_id: DeviceId,
) -> Vec<u8> {
    let mut out = labels::NOTE_AAD.to_vec();
    out.extend_from_slice(&FORMAT.to_be_bytes());
    out.extend_from_slice(server_instance_id.as_bytes());
    out.extend_from_slice(share_id.as_bytes());
    out.extend_from_slice(note_id.as_bytes());
    out.extend_from_slice(&access_epoch.to_be_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(author_device_id.as_bytes());
    out
}

/// What the author device signs. The epoch is excluded on purpose (rekey).
pub fn note_message(
    server_instance_id: Uuid,
    share_id: ShareId,
    n: &SharedNote,
) -> Result<Vec<u8>, SharingValidationError> {
    validate_note(n)?;
    require(!server_instance_id.is_nil(), "server_instance_id")?;
    require(share_id != ShareId::NIL, "share_id")?;
    let mut out = labels::NOTE.to_vec();
    out.extend_from_slice(&FORMAT.to_be_bytes());
    out.extend_from_slice(server_instance_id.as_bytes());
    out.extend_from_slice(share_id.as_bytes());
    out.extend_from_slice(n.note_id.as_bytes());
    out.extend_from_slice(n.author_user_id.as_bytes());
    out.extend_from_slice(n.author_device_id.as_bytes());
    out.extend_from_slice(&n.revision.to_be_bytes());
    out.extend_from_slice(n.payload_hash.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note() -> SharedNote {
        SharedNote {
            note_id: ObjectId::from_uuid(Uuid::from_u128(7)),
            author_user_id: UserId::from_uuid(Uuid::from_u128(2)),
            author_device_id: DeviceId::from_uuid(Uuid::from_u128(3)),
            revision: 1,
            access_epoch: 1,
            nonce: Bytes::new(vec![1; 24]),
            ciphertext: Bytes::new(vec![2; 300]),
            payload_hash: Bytes::new(vec![3; 32]),
            signature: Bytes::new(vec![4; 64]),
        }
    }

    #[test]
    fn note_signature_excludes_the_epoch_and_ciphertext() {
        let instance = Uuid::from_u128(1);
        let share = ShareId::from_uuid(Uuid::from_u128(5));
        let a = note();
        let mut b = a.clone();
        b.access_epoch = 9;
        b.nonce = Bytes::new(vec![9; 24]);
        b.ciphertext = Bytes::new(vec![8; 400]);
        assert_eq!(
            note_message(instance, share, &a).unwrap(),
            note_message(instance, share, &b).unwrap()
        );
        b.revision = 2;
        assert_ne!(
            note_message(instance, share, &a).unwrap(),
            note_message(instance, share, &b).unwrap()
        );
        // The AAD binds the epoch so a ciphertext cannot be replayed into another.
        assert_ne!(
            note_aad(instance, share, a.note_id, 1, 1, a.author_device_id),
            note_aad(instance, share, a.note_id, 2, 1, a.author_device_id)
        );
    }

    #[test]
    fn validation_rejects_malformed_notes_and_rekeys() {
        let mut bad = note();
        bad.payload_hash = Bytes::new(vec![0; 31]);
        assert!(validate_note(&bad).is_err());
        let mut bad = note();
        bad.ciphertext = Bytes::new(vec![0; MAX_NOTE_CIPHERTEXT_BYTES + 1]);
        assert!(validate_note(&bad).is_err());
        let rekey = RekeySharedNotesRequest {
            access_epoch: 2,
            notes: vec![
                RekeyedSharedNote {
                    note_id: ObjectId::from_uuid(Uuid::from_u128(1)),
                    revision: 1,
                    nonce: Bytes::new(vec![0; 24]),
                    ciphertext: Bytes::new(vec![0; 32]),
                };
                2
            ],
        };
        assert_eq!(
            validate_rekey(&rekey),
            Err(SharingValidationError("note_id"))
        );
    }
}
