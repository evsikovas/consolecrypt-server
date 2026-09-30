//! Runtime signatures for server enrollment tests. Challenge bytes are opaque:
//! client AEAD/X25519 possession verification is deliberately outside this suite.
use super::{now_unix, random, sharing::*, Session, TestServer};
use cc_protocol::{sharing::*, sharing_enrollment::*, Bytes, ShareId};
use consolecrypt_server::crypto;
use ed25519_dalek::Signer;
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

pub fn digest(input: Vec<u8>) -> Bytes {
    crypto::sha256(&input).to_vec().into()
}
pub fn signature(signer: &Session, message: &[u8]) -> Bytes {
    signer
        .device
        .signing
        .sign(message)
        .to_bytes()
        .to_vec()
        .into()
}
pub fn grant_hash(value: &SignedSharingOwnDevicesGrantState) -> Bytes {
    digest(enrollment_grant_hash_input(value).unwrap())
}
pub fn request_hash(value: &SignedSharingOwnDeviceRequest) -> Bytes {
    digest(enrollment_request_hash_input(value).unwrap())
}
pub fn endorsement_hash(value: &SignedSharingAnchorEndorsement) -> Bytes {
    digest(enrollment_endorsement_hash_input(value).unwrap())
}
pub fn challenge_hash(value: &SignedSharingDeviceChallenge) -> Bytes {
    digest(enrollment_challenge_hash_input(value).unwrap())
}
pub fn response_hash(value: &SignedSharingDeviceChallengeResponse) -> Bytes {
    digest(enrollment_response_hash_input(value).unwrap())
}
pub fn sign_grant(
    owner: &Session,
    grant: SharingOwnDevicesGrantState,
) -> SignedSharingOwnDevicesGrantState {
    let signature = signature(owner, &enrollment_grant_message(&grant).unwrap());
    SignedSharingOwnDevicesGrantState { grant, signature }
}
pub fn sign_request(
    target: &Session,
    request: SharingOwnDeviceRequest,
) -> SignedSharingOwnDeviceRequest {
    let signature = signature(target, &enrollment_request_message(&request).unwrap());
    SignedSharingOwnDeviceRequest { request, signature }
}
pub fn sign_endorsement(
    anchor: &Session,
    endorsement: SharingAnchorEndorsement,
) -> SignedSharingAnchorEndorsement {
    let signature = signature(
        anchor,
        &enrollment_endorsement_message(&endorsement).unwrap(),
    );
    SignedSharingAnchorEndorsement {
        endorsement,
        signature,
    }
}
pub fn sign_challenge(
    owner: &Session,
    challenge: SharingDeviceChallenge,
) -> SignedSharingDeviceChallenge {
    let signature = signature(owner, &enrollment_challenge_message(&challenge).unwrap());
    SignedSharingDeviceChallenge {
        challenge,
        signature,
    }
}
pub fn sign_response(
    target: &Session,
    response: SharingDeviceChallengeResponse,
) -> SignedSharingDeviceChallengeResponse {
    let signature = signature(target, &enrollment_response_message(&response).unwrap());
    SignedSharingDeviceChallengeResponse {
        response,
        signature,
    }
}
pub fn sign_acceptance(
    owner: &Session,
    acceptance: SharingOwnDeviceAcceptance,
) -> SignedSharingOwnDeviceAcceptance {
    let signature = signature(owner, &enrollment_acceptance_message(&acceptance).unwrap());
    SignedSharingOwnDeviceAcceptance {
        acceptance,
        signature,
    }
}
pub fn binding(session: &Session) -> EnrollmentDeviceBinding {
    EnrollmentDeviceBinding {
        user_id: session.user_id,
        device_id: session.device.id,
        encryption_public_key: session.device.encryption_public_key.to_vec().into(),
        signing_public_key: session.device.signing_public_key().to_vec().into(),
    }
}
pub fn scope(old: &SharedItemState) -> EnrollmentScope {
    let m = &old.access.manifest;
    EnrollmentScope {
        server_instance_id: m.server_instance_id,
        share_id: m.share_id,
        item_id: m.item_id,
        kind: m.kind,
    }
}
pub fn grant(
    owner: &Session,
    anchor: &Session,
    old: &SharedItemState,
    role: SharingRole,
    mode: EnrollmentMode,
    max_admissions: u32,
) -> SignedSharingOwnDevicesGrantState {
    sign_grant(
        owner,
        SharingOwnDevicesGrantState {
            format: cc_protocol::sharing_enrollment::FORMAT,
            scope: scope(old),
            owner_user_id: owner.user_id,
            owner_device_id: owner.device.id,
            grant_id: Uuid::new_v4(),
            grant_revision: 1,
            previous_grant_state_hash: vec![0; 32].into(),
            status: EnrollmentGrantStatus::Active,
            anchor: binding(anchor),
            access_manifest_hash: hash_manifest(&old.access.manifest),
            access_epoch: old.access.manifest.access_epoch,
            role_ceiling: role,
            mode,
            not_before: now_unix() - 5,
            expires_at: now_unix() + 600,
            max_admissions,
            admitted_count: 0,
        },
    )
}
pub fn submission(
    target: &Session,
    anchor: &Session,
    grant: &SignedSharingOwnDevicesGrantState,
    role: SharingRole,
) -> SubmitOwnDeviceRequest {
    let request = sign_request(
        target,
        SharingOwnDeviceRequest {
            format: cc_protocol::sharing_enrollment::FORMAT,
            scope: grant.grant.scope.clone(),
            request_id: Uuid::new_v4(),
            grant_state_hash: grant_hash(grant),
            access_manifest_hash: grant.grant.access_manifest_hash.clone(),
            access_epoch: grant.grant.access_epoch,
            target: binding(target),
            requested_role: role,
            nonce: random::<32>().to_vec().into(),
            not_before: grant.grant.not_before.max(now_unix() - 1),
            expires_at: grant.grant.expires_at.min(now_unix() + 240),
        },
    );
    let endorsement = endorsement(anchor, &request);
    SubmitOwnDeviceRequest {
        grant_id: grant.grant.grant_id,
        request,
        endorsement,
    }
}
pub fn endorsement(
    anchor: &Session,
    request: &SignedSharingOwnDeviceRequest,
) -> SignedSharingAnchorEndorsement {
    sign_endorsement(
        anchor,
        SharingAnchorEndorsement {
            format: cc_protocol::sharing_enrollment::FORMAT,
            request_hash: request_hash(request),
            anchor_device_id: anchor.device.id,
        },
    )
}
pub fn challenge(
    owner: &Session,
    request: &SubmitOwnDeviceRequest,
    generation: u64,
) -> SignedSharingDeviceChallenge {
    sign_challenge(
        owner,
        SharingDeviceChallenge {
            format: cc_protocol::sharing_enrollment::FORMAT,
            request_hash: request_hash(&request.request),
            anchor_endorsement_hash: endorsement_hash(&request.endorsement),
            challenge_id: Uuid::new_v4(),
            generation,
            not_before: request.request.request.not_before.max(now_unix() - 1),
            expires_at: request.request.request.expires_at.min(now_unix() + 120),
            ephemeral_public_key: random::<32>().to_vec().into(),
            nonce: random::<24>().to_vec().into(),
            ciphertext: random::<48>().to_vec().into(),
        },
    )
}
pub fn response(
    target: &Session,
    challenge: &SignedSharingDeviceChallenge,
) -> SignedSharingDeviceChallengeResponse {
    sign_response(
        target,
        SharingDeviceChallengeResponse {
            format: cc_protocol::sharing_enrollment::FORMAT,
            request_hash: challenge.challenge.request_hash.clone(),
            challenge_hash: challenge_hash(challenge),
            response_digest: random::<32>().to_vec().into(),
        },
    )
}
pub fn successor(
    owner: &Session,
    previous: &SignedSharingOwnDevicesGrantState,
    post: &AccessManifest,
    increment: u32,
) -> SignedSharingOwnDevicesGrantState {
    let mut next = previous.grant.clone();
    next.grant_revision += 1;
    next.previous_grant_state_hash = grant_hash(previous);
    next.access_epoch = post.access_epoch;
    next.access_manifest_hash = hash_manifest(post);
    next.admitted_count += increment;
    if next.admitted_count == next.max_admissions {
        next.status = EnrollmentGrantStatus::Revoked;
    }
    sign_grant(owner, next)
}
pub fn revoked(
    owner: &Session,
    previous: &SignedSharingOwnDevicesGrantState,
) -> SignedSharingOwnDevicesGrantState {
    let mut next = previous.grant.clone();
    next.grant_revision += 1;
    next.previous_grant_state_hash = grant_hash(previous);
    next.status = EnrollmentGrantStatus::Revoked;
    sign_grant(owner, next)
}
pub fn acceptance(
    owner: &Session,
    target: &Session,
    old: &SharedItemState,
    grant: &SignedSharingOwnDevicesGrantState,
    request: &SubmitOwnDeviceRequest,
    challenge: &SignedSharingDeviceChallenge,
    response: &SignedSharingDeviceChallengeResponse,
) -> AcceptOwnDeviceRequest {
    let mut members = old.access.manifest.members.clone();
    members.push(member(target, request.request.request.requested_role));
    let rotation = rotation(owner, old, members);
    let consumed_grant_successor = successor(owner, grant, &rotation.access.manifest, 1);
    let acceptance = sign_acceptance(
        owner,
        SharingOwnDeviceAcceptance {
            format: cc_protocol::sharing_enrollment::FORMAT,
            request_hash: request_hash(&request.request),
            anchor_endorsement_hash: endorsement_hash(&request.endorsement),
            challenge_hash: challenge_hash(challenge),
            response_hash: response_hash(response),
            consumed_grant_state_hash: grant_hash(grant),
            result_access_manifest_hash: hash_manifest(&rotation.access.manifest),
            result_revision_hash: hash_revision(&rotation.revision),
            consumed_grant_successor_hash: grant_hash(&consumed_grant_successor),
            other_grant_successor_hashes: vec![],
        },
    );
    AcceptOwnDeviceRequest {
        rotation,
        acceptance,
        consumed_grant_successor,
        other_grant_successors: vec![],
    }
}
/// Re-sign a deliberately modified rotation/successor without fixing its
/// authorization semantics, so negative tests exercise backend checks.
pub fn resign_acceptance(owner: &Session, value: &mut AcceptOwnDeviceRequest) {
    let a = &mut value.acceptance.acceptance;
    a.result_access_manifest_hash = hash_manifest(&value.rotation.access.manifest);
    a.result_revision_hash = hash_revision(&value.rotation.revision);
    a.consumed_grant_successor_hash = grant_hash(&value.consumed_grant_successor);
    a.other_grant_successor_hashes = value
        .other_grant_successors
        .iter()
        .map(|g| EnrollmentGrantSuccessorHash {
            grant_id: g.grant.grant_id,
            state_hash: grant_hash(g),
        })
        .collect();
    value.acceptance = sign_acceptance(owner, a.clone());
}
pub fn grants_path(id: ShareId) -> String {
    format!("{}/own-device-grants", path(id))
}
pub fn grant_path(id: ShareId, grant: Uuid) -> String {
    format!("{}/{grant}", grants_path(id))
}
pub fn requests_path(id: ShareId) -> String {
    format!("{}/own-device-requests", path(id))
}
pub fn request_path(id: ShareId, request: Uuid) -> String {
    format!("{}/{request}", requests_path(id))
}
pub async fn post<T: DeserializeOwned>(
    srv: &TestServer,
    caller: &Session,
    path: &str,
    value: &impl Serialize,
) -> T {
    let (status, body) = srv.post(path, Some(&caller.access), value).await;
    assert!(status.is_success(), "POST {path}: {status}, {body}");
    serde_json::from_value(body).expect("typed enrollment response")
}
pub async fn get<T: DeserializeOwned>(srv: &TestServer, caller: &Session, path: &str) -> T {
    let (status, body) = srv.get(path, &caller.access).await;
    assert!(status.is_success(), "GET {path}: {status}, {body}");
    serde_json::from_value(body).expect("typed enrollment response")
}
pub async fn publish_grant(
    srv: &TestServer,
    owner: &Session,
    value: &SignedSharingOwnDevicesGrantState,
) -> SignedSharingOwnDevicesGrantState {
    post(
        srv,
        owner,
        &grants_path(value.grant.scope.share_id),
        &PublishOwnDevicesGrantRequest {
            grant: value.clone(),
        },
    )
    .await
}
pub async fn respond(
    srv: &TestServer,
    owner: &Session,
    target: &Session,
    request: &SubmitOwnDeviceRequest,
) -> (
    SignedSharingDeviceChallenge,
    SignedSharingDeviceChallengeResponse,
) {
    let p = request_path(
        request.request.request.scope.share_id,
        request.request.request.request_id,
    );
    let challenge = challenge(owner, request, 1);
    let state: OwnDeviceRequestState = post(
        srv,
        owner,
        &format!("{p}/challenge"),
        &PublishOwnDeviceChallengeRequest {
            challenge: challenge.clone(),
        },
    )
    .await;
    assert_eq!(state.status, OwnDeviceRequestStatus::Challenged);
    let response = response(target, &challenge);
    let state: OwnDeviceRequestState = post(
        srv,
        target,
        &format!("{p}/response"),
        &SubmitOwnDeviceChallengeResponseRequest {
            response: response.clone(),
        },
    )
    .await;
    assert_eq!(state.status, OwnDeviceRequestStatus::Responded);
    (challenge, response)
}
