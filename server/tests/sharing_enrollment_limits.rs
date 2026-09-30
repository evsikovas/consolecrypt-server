// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Quota boundary tests use bulk SQL only to reconstruct retained history.
//! Every stored document has real runtime signatures, matching hashes/index
//! columns and a complete grant chain. HTTP exercises both sides of each limit.
//! Historical requests model completed expiry windows; no clock, signature or
//! authorization validation is disabled in production or in the boundary call.
mod common;

use cc_protocol::{sharing::*, sharing_enrollment::*, ShareId};
use common::{enrollment as en, sharing::*, *};
use consolecrypt_server::Config;
use reqwest::StatusCode;
use sqlx::{types::Json, Postgres, QueryBuilder};
use uuid::Uuid;

fn enabled(c: &mut Config) {
    c.object_sharing_enabled = true;
    c.sharing_owner_online_enrollment_enabled = true;
}
struct Fixture {
    owner: Session,
    anchor: Session,
    target: Session,
    old: SharedItemState,
}
impl Fixture {
    async fn new(srv: &TestServer) -> Self {
        let owner = srv.new_account().await;
        let anchor = srv.new_account().await;
        let target = srv.new_device_session(&anchor, "quota target").await;
        let old = create(srv, &owner, &[(&anchor, SharingRole::Reader)]).await;
        Self {
            owner,
            anchor,
            target,
            old,
        }
    }
    fn id(&self) -> ShareId {
        self.old.access.manifest.share_id
    }
    fn grant(&self) -> SignedSharingOwnDevicesGrantState {
        en::grant(
            &self.owner,
            &self.anchor,
            &self.old,
            SharingRole::Reader,
            EnrollmentMode::Manual,
            2,
        )
    }
    fn request(&self, grant: &SignedSharingOwnDevicesGrantState) -> SubmitOwnDeviceRequest {
        en::submission(&self.target, &self.anchor, grant, SharingRole::Reader)
    }
    async fn submit(
        &self,
        srv: &TestServer,
        request: &SubmitOwnDeviceRequest,
    ) -> OwnDeviceRequestState {
        en::post(srv, &self.target, &en::requests_path(self.id()), request).await
    }
}
fn pending(submission: SubmitOwnDeviceRequest) -> OwnDeviceRequestState {
    let value = OwnDeviceRequestState {
        grant_id: submission.grant_id,
        request: submission.request,
        endorsement: submission.endorsement,
        status: OwnDeviceRequestStatus::Pending,
        challenge: None,
        response: None,
        acceptance: None,
    };
    validate_request_state(&value).unwrap();
    value
}
fn set_request_lifetime(f: &Fixture, value: &mut SubmitOwnDeviceRequest, start: i64, end: i64) {
    value.request.request.not_before = start;
    value.request.request.expires_at = end;
    value.request = en::sign_request(&f.target, value.request.request.clone());
    value.endorsement = en::endorsement(&f.anchor, &value.request);
}
async fn seed_grant_chains(srv: &TestServer, chains: &[Vec<SignedSharingOwnDevicesGrantState>]) {
    // This fixture setup does not invoke the production store helper: explicit
    // columns make inconsistencies between signed and quota data visible here.
    for chain in chains {
        assert_eq!(chain.first().unwrap().grant.grant_revision, 1);
        for value in chain {
            validate_signed_grant(value).unwrap();
        }
        for pair in chain.windows(2) {
            assert_eq!(
                pair[1].grant.previous_grant_state_hash,
                en::grant_hash(&pair[0])
            );
            assert_eq!(
                pair[1].grant.grant_revision,
                pair[0].grant.grant_revision + 1
            );
        }
    }
    let mut tx = srv.state.db.begin().await.unwrap();
    let mut heads = QueryBuilder::<Postgres>::new(
        "INSERT INTO shared_enrollment_grants (share_id,grant_id,revision,state_hash,access_manifest_hash,not_before,anchor_user_id,anchor_device_id,status,expires_at,document) ",
    );
    heads.push_values(chains, |mut row, chain| {
        let signed = chain.last().unwrap();
        let g = &signed.grant;
        row.push_bind(Uuid::from(g.scope.share_id))
            .push_bind(g.grant_id)
            .push_bind(g.grant_revision as i64)
            .push_bind(en::grant_hash(signed).as_slice().to_vec())
            .push_bind(g.access_manifest_hash.as_slice())
            .push_bind(g.not_before)
            .push_bind(Uuid::from(g.anchor.user_id))
            .push_bind(Uuid::from(g.anchor.device_id))
            .push_bind(if g.status == EnrollmentGrantStatus::Active {
                "active"
            } else {
                "revoked"
            })
            .push_bind(g.expires_at)
            .push_bind(Json(signed));
    });
    heads.build().execute(&mut *tx).await.unwrap();
    let mut history = QueryBuilder::<Postgres>::new(
        "INSERT INTO shared_enrollment_grant_states (share_id,grant_id,revision,state_hash,document) ",
    );
    history.push_values(chains.iter().flatten(), |mut row, signed| {
        row.push_bind(Uuid::from(signed.grant.scope.share_id))
            .push_bind(signed.grant.grant_id)
            .push_bind(signed.grant.grant_revision as i64)
            .push_bind(en::grant_hash(signed).as_slice().to_vec())
            .push_bind(Json(signed));
    });
    history.build().execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}
async fn seed_requests(srv: &TestServer, values: &[OwnDeviceRequestState]) {
    for value in values {
        validate_request_state(value).unwrap();
    }
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO shared_enrollment_requests (share_id,request_id,grant_id,grant_state_hash,request_hash,nonce,target_user_id,target_device_id,expires_at,document) ",
    );
    query.push_values(values, |mut row, value| {
        let r = &value.request.request;
        row.push_bind(Uuid::from(r.scope.share_id))
            .push_bind(r.request_id)
            .push_bind(value.grant_id)
            .push_bind(r.grant_state_hash.as_slice())
            .push_bind(en::request_hash(&value.request).as_slice().to_vec())
            .push_bind(r.nonce.as_slice())
            .push_bind(Uuid::from(r.target.user_id))
            .push_bind(Uuid::from(r.target.device_id))
            .push_bind(r.expires_at)
            .push_bind(Json(value));
    });
    query.build().execute(&srv.state.db).await.unwrap();
}
async fn retained_counts(srv: &TestServer, id: ShareId) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM shared_enrollment_grants WHERE share_id=$1),
                (SELECT count(*) FROM shared_enrollment_requests WHERE share_id=$1)",
    )
    .bind(Uuid::from(id))
    .fetch_one(&srv.state.db)
    .await
    .unwrap()
}
async fn reject_grant(
    srv: &TestServer,
    f: &Fixture,
    grant: SignedSharingOwnDevicesGrantState,
    expected: StatusCode,
) {
    assert_eq!(
        srv.post(
            &en::grants_path(f.id()),
            Some(&f.owner.access),
            &PublishOwnDevicesGrantRequest { grant }
        )
        .await
        .0,
        expected
    );
}
async fn reject_request(
    srv: &TestServer,
    f: &Fixture,
    value: &SubmitOwnDeviceRequest,
    expected: StatusCode,
) {
    assert_eq!(
        srv.post(&en::requests_path(f.id()), Some(&f.target.access), value)
            .await
            .0,
        expected
    );
}

#[tokio::test]
async fn active_and_retained_grant_limits_are_distinct_and_never_recycle_ids() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv).await;
    let chains: Vec<_> = (0..MAX_GRANTS_PER_SHARE - 1)
        .map(|_| vec![f.grant()])
        .collect();
    seed_grant_chains(&srv, &chains).await;
    let last = f.grant();
    assert_eq!(en::publish_grant(&srv, &f.owner, &last).await, last);
    assert_eq!(
        retained_counts(&srv, f.id()).await,
        (MAX_GRANTS_PER_SHARE as i64, 0)
    );
    let blocked = f.grant();
    reject_grant(&srv, &f, blocked.clone(), StatusCode::FORBIDDEN).await;
    let first = &chains[0][0];
    let stopped = en::revoked(&f.owner, first);
    en::publish_grant(&srv, &f.owner, &stopped).await;
    // A terminal ID remains occupied even after an active slot was freed.
    reject_grant(&srv, &f, first.clone(), StatusCode::CONFLICT).await;
    assert_eq!(en::publish_grant(&srv, &f.owner, &blocked).await, blocked);
    // Sixteen current active grants become stale after ordinary v1 rotation;
    // they retain all IDs/history but no longer occupy the active-head quota.
    let next = rotation(&f.owner, &f.old, f.old.access.manifest.members.clone());
    let post: SharedItemState =
        en::post(&srv, &f.owner, &format!("{}/access", path(f.id())), &next).await;
    let fresh = en::grant(
        &f.owner,
        &f.anchor,
        &post,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        2,
    );
    en::publish_grant(&srv, &f.owner, &fresh).await;
    assert_eq!(
        retained_counts(&srv, f.id()).await,
        (MAX_GRANTS_PER_SHARE as i64 + 2, 0)
    );
    let head: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &f.owner,
        &en::grant_path(f.id(), first.grant.grant_id),
    )
    .await;
    assert_eq!(head, stopped);

    let retained = Fixture::new(&srv).await;
    // A mixture of terminal and expired Active heads models preserved old
    // chains. Neither kind should consume the current active-head quota.
    let mut chains = Vec::new();
    for index in 0..MAX_RETAINED_GRANTS_PER_SHARE - 1 {
        let mut g = retained.grant();
        if index % 2 == 0 {
            let stop = en::revoked(&retained.owner, &g);
            chains.push(vec![g, stop]);
        } else {
            g.grant.not_before = now_unix() - 120;
            g.grant.expires_at = now_unix() - 60;
            g = en::sign_grant(&retained.owner, g.grant);
            chains.push(vec![g]);
        }
    }
    seed_grant_chains(&srv, &chains).await;
    let final_slot = retained.grant();
    en::publish_grant(&srv, &retained.owner, &final_slot).await;
    assert_eq!(
        retained_counts(&srv, retained.id()).await,
        (MAX_RETAINED_GRANTS_PER_SHARE as i64, 0)
    );
    reject_grant(&srv, &retained, retained.grant(), StatusCode::FORBIDDEN).await;
    // Terminal transitions and recovery still work at the retained ceiling.
    let stop = en::revoked(&retained.owner, &final_slot);
    en::publish_grant(&srv, &retained.owner, &stop).await;
    reject_grant(&srv, &retained, retained.grant(), StatusCode::FORBIDDEN).await;
    let recovered: SignedSharingOwnDevicesGrantState = en::get(
        &srv,
        &retained.owner,
        &en::grant_path(retained.id(), stop.grant.grant_id),
    )
    .await;
    assert_eq!(recovered, stop);
    assert_eq!(
        retained_counts(&srv, retained.id()).await,
        (MAX_RETAINED_GRANTS_PER_SHARE as i64, 0)
    );
}

#[tokio::test]
async fn pending_grant_limit_releases_expired_slots_but_retains_request_ids_and_nonces() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv).await;
    let grant = f.grant();
    en::publish_grant(&srv, &f.owner, &grant).await;
    let mut requests = Vec::new();
    let mut expiring = f.request(&grant);
    let deadline = now_unix() + 5;
    set_request_lifetime(&f, &mut expiring, grant.grant.not_before, deadline);
    requests.push(pending(expiring.clone()));
    for _ in 1..MAX_PENDING_REQUESTS_PER_GRANT - 1 {
        requests.push(pending(f.request(&grant)));
    }
    seed_requests(&srv, &requests).await;
    let last = f.request(&grant);
    assert_eq!(
        f.submit(&srv, &last).await.status,
        OwnDeviceRequestStatus::Pending
    );
    let blocked = f.request(&grant);
    reject_request(&srv, &f, &blocked, StatusCode::FORBIDDEN).await;
    assert!(
        now_unix() < deadline,
        "quota rejection must happen before fixture expiry"
    );
    let wait = (deadline - now_unix()).max(0) as u64 + 1;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    let expired: OwnDeviceRequestState = en::get(
        &srv,
        &f.target,
        &en::request_path(f.id(), expiring.request.request.request_id),
    )
    .await;
    assert_eq!(expired.status, OwnDeviceRequestStatus::Expired);
    // Re-sign valid fresh requests so these fail due to retained uniqueness,
    // not due to their old timestamps or a now-available quota slot.
    let mut reused_id = f.request(&grant);
    reused_id.request.request.request_id = expiring.request.request.request_id;
    reused_id.request = en::sign_request(&f.target, reused_id.request.request);
    reused_id.endorsement = en::endorsement(&f.anchor, &reused_id.request);
    reject_request(&srv, &f, &reused_id, StatusCode::CONFLICT).await;
    let mut reused_nonce = f.request(&grant);
    reused_nonce.request.request.nonce = expiring.request.request.nonce.clone();
    reused_nonce.request = en::sign_request(&f.target, reused_nonce.request.request);
    reused_nonce.endorsement = en::endorsement(&f.anchor, &reused_nonce.request);
    reject_request(&srv, &f, &reused_nonce, StatusCode::CONFLICT).await;
    assert_eq!(
        f.submit(&srv, &blocked).await.status,
        OwnDeviceRequestStatus::Pending
    );
    reject_request(&srv, &f, &f.request(&grant), StatusCode::FORBIDDEN).await;
    assert_eq!(
        retained_counts(&srv, f.id()).await,
        (1, MAX_PENDING_REQUESTS_PER_GRANT as i64 + 1)
    );
    let stored: Json<OwnDeviceRequestState> = sqlx::query_scalar(
        "SELECT document FROM shared_enrollment_requests WHERE share_id=$1 AND request_id=$2",
    )
    .bind(Uuid::from(f.id()))
    .bind(expiring.request.request.request_id)
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(stored.request, expiring.request);
    assert_eq!(stored.endorsement, expiring.endorsement);
}

#[tokio::test]
async fn pending_share_limit_releases_revoked_and_stale_grants_without_recycling_requests() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv).await;
    let grant_count = MAX_PENDING_REQUESTS_PER_SHARE / MAX_PENDING_REQUESTS_PER_GRANT;
    let chains: Vec<_> = (0..grant_count + 1).map(|_| vec![f.grant()]).collect();
    seed_grant_chains(&srv, &chains).await;
    let mut requests = Vec::new();
    for (index, chain) in chains.iter().take(grant_count).enumerate() {
        let count = MAX_PENDING_REQUESTS_PER_GRANT - usize::from(index + 1 == grant_count);
        for _ in 0..count {
            requests.push(pending(f.request(&chain[0])));
        }
    }
    seed_requests(&srv, &requests).await;
    let last = f.request(&chains[grant_count - 1][0]);
    assert_eq!(
        f.submit(&srv, &last).await.status,
        OwnDeviceRequestStatus::Pending
    );
    let blocked = f.request(&chains[grant_count][0]);
    // Its own grant has zero requests; only the share-wide quota can reject it.
    reject_request(&srv, &f, &blocked, StatusCode::FORBIDDEN).await;
    let stopped = en::revoked(&f.owner, &chains[0][0]);
    en::publish_grant(&srv, &f.owner, &stopped).await;
    assert_eq!(
        f.submit(&srv, &blocked).await.status,
        OwnDeviceRequestStatus::Pending
    );
    assert_eq!(
        retained_counts(&srv, f.id()).await.1,
        MAX_PENDING_REQUESTS_PER_SHARE as i64 + 1
    );
    let rotate = rotation(&f.owner, &f.old, f.old.access.manifest.members.clone());
    let post: SharedItemState =
        en::post(&srv, &f.owner, &format!("{}/access", path(f.id())), &rotate).await;
    let fresh_grant = en::grant(
        &f.owner,
        &f.anchor,
        &post,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        2,
    );
    en::publish_grant(&srv, &f.owner, &fresh_grant).await;
    let stale = f.request(&chains[1][0]);
    reject_request(&srv, &f, &stale, StatusCode::CONFLICT).await;
    let mut reused_id = f.request(&fresh_grant);
    reused_id.request.request.request_id = requests[0].request.request.request_id;
    reused_id.request = en::sign_request(&f.target, reused_id.request.request);
    reused_id.endorsement = en::endorsement(&f.anchor, &reused_id.request);
    reject_request(&srv, &f, &reused_id, StatusCode::CONFLICT).await;
    let fresh = f.request(&fresh_grant);
    assert_eq!(
        f.submit(&srv, &fresh).await.status,
        OwnDeviceRequestStatus::Pending
    );
    assert_eq!(
        retained_counts(&srv, f.id()).await.1,
        MAX_PENDING_REQUESTS_PER_SHARE as i64 + 2
    );
    for old in [&requests[0], &requests[MAX_PENDING_REQUESTS_PER_GRANT]] {
        let state: OwnDeviceRequestState = en::get(
            &srv,
            &f.target,
            &en::request_path(f.id(), old.request.request.request_id),
        )
        .await;
        assert_eq!(state.status, OwnDeviceRequestStatus::Denied);
        assert_eq!(state.request, old.request);
        assert_eq!(state.endorsement, old.endorsement);
    }
}

#[tokio::test]
async fn retained_request_limit_survives_expiry_and_grant_revoke() {
    let srv = server!(enabled);
    let f = Fixture::new(&srv).await;
    let mut historical = f.grant();
    historical.grant.not_before = now_unix() - 24 * 60 * 60;
    historical.grant.expires_at = now_unix() - 60;
    historical = en::sign_grant(&f.owner, historical.grant);
    seed_grant_chains(&srv, &[vec![historical.clone()]]).await;
    let mut requests = Vec::new();
    // Start from a structurally valid current request, then bind and re-sign
    // its historical grant and nested dates before persisting the fixture.
    let template = f.grant();
    for index in 0..MAX_RETAINED_REQUESTS_PER_SHARE - 1 {
        let mut request = f.request(&template);
        request.grant_id = historical.grant.grant_id;
        request.request.request.grant_state_hash = en::grant_hash(&historical);
        // Each past wave contains at most16 simultaneous requests. Complete
        // signed request lifetimes are nested inside the historical grant.
        let start =
            historical.grant.not_before + (index / MAX_PENDING_REQUESTS_PER_GRANT) as i64 * 60;
        set_request_lifetime(&f, &mut request, start, start + 30);
        validate_request_for_grant(&request.request.request, &historical.grant).unwrap();
        requests.push(pending(request));
    }
    seed_requests(&srv, &requests).await;
    let live_grant = f.grant();
    en::publish_grant(&srv, &f.owner, &live_grant).await;
    let last = f.request(&live_grant);
    assert_eq!(
        f.submit(&srv, &last).await.status,
        OwnDeviceRequestStatus::Pending
    );
    assert_eq!(
        retained_counts(&srv, f.id()).await.1,
        MAX_RETAINED_REQUESTS_PER_SHARE as i64
    );
    reject_request(&srv, &f, &f.request(&live_grant), StatusCode::FORBIDDEN).await;
    let stop = en::revoked(&f.owner, &live_grant);
    en::publish_grant(&srv, &f.owner, &stop).await;
    let another = f.grant();
    en::publish_grant(&srv, &f.owner, &another).await;
    // No live pending requests remain, but the retained1024 ceiling remains.
    reject_request(&srv, &f, &f.request(&another), StatusCode::FORBIDDEN).await;
    let old: OwnDeviceRequestState = en::get(
        &srv,
        &f.target,
        &en::request_path(f.id(), requests[0].request.request.request_id),
    )
    .await;
    assert_eq!(old.status, OwnDeviceRequestStatus::Expired);
    assert_eq!(old.request, requests[0].request);
    let final_state: OwnDeviceRequestState = en::get(
        &srv,
        &f.target,
        &en::request_path(f.id(), last.request.request.request_id),
    )
    .await;
    assert_eq!(final_state.status, OwnDeviceRequestStatus::Denied);
    assert_eq!(
        retained_counts(&srv, f.id()).await.1,
        MAX_RETAINED_REQUESTS_PER_SHARE as i64
    );
}
