//! Real signatures over runtime-generated opaque ciphertext.
use super::*;
use cc_protocol::{sharing::*, Bytes, MutationId, ObjectId, ShareId};
use consolecrypt_server::{auth::AuthContext, crypto, sharing::service};
use ed25519_dalek::Signer;
use uuid::Uuid;
pub fn context(s: &Session) -> AuthContext {
    AuthContext {
        user_id: s.user_id,
        device_id: s.device.id,
        session_id: s.session_id,
        email_verified: false,
        access_token_hash: crypto::sha256(s.access.as_bytes()),
    }
}
pub fn member(s: &Session, role: SharingRole) -> SharingMember {
    SharingMember {
        user_id: s.user_id,
        device_id: s.device.id,
        encryption_public_key: s.device.encryption_public_key.to_vec().into(),
        signing_public_key: s.device.signing_public_key().to_vec().into(),
        role,
    }
}
pub fn sign_manifest(owner: &Session, manifest: AccessManifest) -> SignedAccessManifest {
    let signature = owner
        .device
        .signing
        .sign(&sharing_manifest_message(&manifest).unwrap())
        .to_bytes()
        .to_vec()
        .into();
    SignedAccessManifest {
        manifest,
        signature,
    }
}
pub fn hash_manifest(m: &AccessManifest) -> Bytes {
    crypto::sha256(&sharing_manifest_message(m).unwrap())
        .to_vec()
        .into()
}
pub fn hash_revision(r: &SharedRevision) -> Bytes {
    crypto::sha256(&sharing_mutation_message(&r.signed.mutation).unwrap())
        .to_vec()
        .into()
}
pub fn sign_revision(s: &Session, r: &mut SharedRevision) {
    r.signed.mutation.body_hash = r
        .body
        .as_ref()
        .map(|b| {
            crypto::sha256(&sharing_body_message(b).unwrap())
                .to_vec()
                .into()
        })
        .unwrap_or_else(|| vec![0; 32].into());
    r.signed.signature = s
        .device
        .signing
        .sign(&sharing_mutation_message(&r.signed.mutation).unwrap())
        .to_bytes()
        .to_vec()
        .into();
}
pub fn revision(
    writer: &Session,
    m: &AccessManifest,
    prior: Option<&SharedRevision>,
) -> SharedRevision {
    let base_revision = prior.map_or(0, |v| v.signed.mutation.context.revision);
    let body = SharedEncryptedBody {
        format: FORMAT,
        ciphertext: random::<80>().to_vec().into(),
        nonce: random::<24>().to_vec().into(),
        envelopes: m
            .members
            .iter()
            .map(|v| SharedKeyEnvelope {
                recipient_device_id: v.device_id,
                ephemeral_public_key: random::<32>().to_vec().into(),
                nonce: random::<24>().to_vec().into(),
                ciphertext: random::<48>().to_vec().into(),
            })
            .collect(),
    };
    let mut r = SharedRevision {
        signed: SignedSharingMutation {
            mutation: SharingMutation {
                context: SharingContext {
                    server_instance_id: m.server_instance_id,
                    share_id: m.share_id,
                    item_id: m.item_id,
                    revision: base_revision + 1,
                    access_epoch: m.access_epoch,
                    kind: m.kind,
                },
                mutation_id: MutationId::new(),
                base_revision,
                manifest_revision: m.revision,
                manifest_hash: hash_manifest(m),
                writer_device_id: writer.device.id,
                previous_revision_hash: prior
                    .map(hash_revision)
                    .unwrap_or_else(|| vec![0; 32].into()),
                operation: SharingOperation::Put,
                body_hash: vec![0; 32].into(),
            },
            signature: Bytes::default(),
        },
        body: Some(body),
    };
    sign_revision(writer, &mut r);
    r
}
pub async fn request(
    srv: &TestServer,
    owner: &Session,
    others: &[(&Session, SharingRole)],
) -> CreateShareRequest {
    let instance: Uuid =
        sqlx::query_scalar("SELECT instance_id FROM sharing_instance WHERE singleton")
            .fetch_one(&srv.state.db)
            .await
            .unwrap();
    let mut members = vec![member(owner, SharingRole::Editor)];
    members.extend(others.iter().map(|(s, r)| member(s, *r)));
    let m = AccessManifest {
        format: FORMAT,
        server_instance_id: instance,
        share_id: ShareId::new(),
        item_id: ObjectId::new(),
        owner_user_id: owner.user_id,
        owner_device_id: owner.device.id,
        revision: 1,
        access_epoch: 1,
        previous_manifest_hash: vec![0; 32].into(),
        kind: SharedItemKind::Host,
        members,
    };
    let revision = revision(owner, &m, None);
    CreateShareRequest {
        access: sign_manifest(owner, m),
        revision,
    }
}
pub async fn create(
    srv: &TestServer,
    owner: &Session,
    others: &[(&Session, SharingRole)],
) -> SharedItemState {
    service::create(
        &srv.state,
        &context(owner),
        request(srv, owner, others).await,
    )
    .await
    .unwrap()
}
pub fn rotation(
    owner: &Session,
    old: &SharedItemState,
    members: Vec<SharingMember>,
) -> RotateShareAccessRequest {
    let mut m = old.access.manifest.clone();
    m.revision += 1;
    m.access_epoch += 1;
    m.previous_manifest_hash = hash_manifest(&old.access.manifest);
    m.members = members;
    let revision = revision(owner, &m, Some(&old.revision));
    RotateShareAccessRequest {
        access: sign_manifest(owner, m),
        revision,
    }
}
pub fn path(id: ShareId) -> String {
    format!("/v1/shares/{id}")
}
