// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use cc_protocol::{sharing::*, sharing_notes::*, ObjectId};
use common::{sharing::*, *};
use ed25519_dalek::Signer;
use reqwest::{Method, StatusCode};

fn notes_server_config(c: &mut consolecrypt_server::config::Config) {
    c.object_sharing_enabled = true;
    c.shared_notes_enabled = true;
}

fn key_set(owner: &Session, state: &SharedItemState) -> SharedNotesKeySet {
    let m = &state.access.manifest;
    let mut set = SharedNotesKeySet {
        format: cc_protocol::sharing_notes::FORMAT,
        server_instance_id: m.server_instance_id,
        share_id: m.share_id,
        access_epoch: m.access_epoch,
        manifest_hash: hash_manifest(m),
        owner_device_id: m.owner_device_id,
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
        signature: vec![0; 64].into(),
    };
    set.signature = owner
        .device
        .signing
        .sign(&notes_key_set_message(&set).unwrap())
        .to_bytes()
        .to_vec()
        .into();
    set
}

fn note(author: &Session, state: &SharedItemState, note_id: ObjectId, revision: u64) -> SharedNote {
    let m = &state.access.manifest;
    let mut n = SharedNote {
        note_id,
        author_user_id: author.user_id,
        author_device_id: author.device.id,
        revision,
        access_epoch: m.access_epoch,
        nonce: random::<24>().to_vec().into(),
        ciphertext: random::<300>().to_vec().into(),
        payload_hash: random::<32>().to_vec().into(),
        signature: vec![0; 64].into(),
    };
    n.signature = author
        .device
        .signing
        .sign(&note_message(m.server_instance_id, m.share_id, &n).unwrap())
        .to_bytes()
        .to_vec()
        .into();
    n
}

async fn put<B: serde::Serialize>(
    srv: &TestServer,
    path: &str,
    s: &Session,
    body: &B,
) -> StatusCode {
    srv.request(Method::PUT, path, Some(&s.access), Some(body))
        .await
        .0
}

fn notes(state: &SharedItemState) -> String {
    format!("{}/notes", path(state.access.manifest.share_id))
}

async fn page(
    srv: &TestServer,
    state: &SharedItemState,
    s: &Session,
) -> (StatusCode, SharedNotesPage) {
    let (code, body) = srv.get(&notes(state), &s.access).await;
    let page = serde_json::from_value(body).unwrap_or(SharedNotesPage {
        access_epoch: 0,
        key_sets: vec![],
        notes: vec![],
    });
    (code, page)
}

#[tokio::test]
async fn notes_are_off_unless_enabled_and_advertised() {
    let srv = server!(|c| c.object_sharing_enabled = true);
    let owner = srv.new_account().await;
    let state = create(&srv, &owner, &[]).await;
    assert_eq!(
        srv.get(&notes(&state), &owner.access).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, caps) = srv.get("/v1/shares/capabilities", &owner.access).await;
    assert_eq!(caps["supports_notes_v1"], false);
    let srv = server!(notes_server_config);
    let owner = srv.new_account().await;
    let (_, caps) = srv.get("/v1/shares/capabilities", &owner.access).await;
    assert_eq!(caps["supports_notes_v1"], true);
}

#[tokio::test]
async fn members_write_their_own_notes_under_the_owner_key() {
    let srv = server!(notes_server_config);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let stranger = srv.new_account().await;
    let state = create(&srv, &owner, &[(&reader, SharingRole::Reader)]).await;
    let keys = format!("{}/keys", notes(&state));

    // No key yet: notes wait for the owner.
    let first = ObjectId::new();
    let path_of = |id: ObjectId| format!("{}/{id}", notes(&state));
    assert_eq!(
        put(
            &srv,
            &path_of(first),
            &reader,
            &note(&reader, &state, first, 1)
        )
        .await,
        StatusCode::CONFLICT
    );

    // Only the owner device publishes the key, with envelopes for every member.
    assert_eq!(
        put(&srv, &keys, &reader, &key_set(&reader, &state)).await,
        StatusCode::FORBIDDEN
    );
    let mut partial = key_set(&owner, &state);
    partial.envelopes.pop();
    partial.signature = owner
        .device
        .signing
        .sign(&notes_key_set_message(&partial).unwrap())
        .to_bytes()
        .to_vec()
        .into();
    assert_eq!(
        put(&srv, &keys, &owner, &partial).await,
        StatusCode::BAD_REQUEST
    );
    let mut forged = key_set(&owner, &state);
    forged.signature = random::<64>().to_vec().into();
    assert_ne!(put(&srv, &keys, &owner, &forged).await, StatusCode::CREATED);
    let set = key_set(&owner, &state);
    assert_eq!(put(&srv, &keys, &owner, &set).await, StatusCode::CREATED);
    assert_eq!(put(&srv, &keys, &owner, &set).await, StatusCode::OK);
    assert_eq!(
        put(&srv, &keys, &owner, &key_set(&owner, &state)).await,
        StatusCode::CONFLICT
    );

    // A reader writes; the owner reads; strangers see nothing.
    let n = note(&reader, &state, first, 1);
    assert_eq!(
        put(&srv, &path_of(first), &reader, &n).await,
        StatusCode::OK
    );
    let (code, p) = page(&srv, &state, &owner).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(p.notes, vec![n.clone()]);
    assert_eq!(p.key_sets, vec![set]);
    assert_eq!(
        srv.get(&notes(&state), &stranger.access).await.0,
        StatusCode::NOT_FOUND
    );

    // Revisions advance one by one; a forged signature or another author is refused.
    assert_eq!(
        put(
            &srv,
            &path_of(first),
            &reader,
            &note(&reader, &state, first, 1)
        )
        .await,
        StatusCode::CONFLICT
    );
    let mut bad = note(&reader, &state, first, 2);
    bad.payload_hash = random::<32>().to_vec().into();
    assert_ne!(
        put(&srv, &path_of(first), &reader, &bad).await,
        StatusCode::OK
    );
    assert_eq!(
        put(
            &srv,
            &path_of(first),
            &owner,
            &note(&owner, &state, first, 2)
        )
        .await,
        StatusCode::FORBIDDEN
    );
    let mut spoofed = note(&reader, &state, first, 2);
    spoofed.author_user_id = owner.user_id;
    assert_eq!(
        put(&srv, &path_of(first), &reader, &spoofed).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put(
            &srv,
            &path_of(first),
            &reader,
            &note(&reader, &state, first, 2)
        )
        .await,
        StatusCode::OK
    );

    // The owner removes anyone's note; a reader removes only its own.
    let mine = ObjectId::new();
    assert_eq!(
        put(&srv, &path_of(mine), &owner, &note(&owner, &state, mine, 1)).await,
        StatusCode::OK
    );
    assert_eq!(
        srv.delete::<()>(&path_of(mine), &reader.access, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        srv.delete::<()>(&path_of(first), &owner.access, None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(page(&srv, &state, &reader).await.1.notes.len(), 1);
}

#[tokio::test]
async fn rotation_cuts_off_removed_members_and_rekey_keeps_authorship() {
    let srv = server!(notes_server_config);
    let owner = srv.new_account().await;
    let reader = srv.new_account().await;
    let leaver = srv.new_account().await;
    let state = create(
        &srv,
        &owner,
        &[
            (&reader, SharingRole::Reader),
            (&leaver, SharingRole::Reader),
        ],
    )
    .await;
    let keys = format!("{}/keys", notes(&state));
    assert_eq!(
        put(&srv, &keys, &owner, &key_set(&owner, &state)).await,
        StatusCode::CREATED
    );
    let id = ObjectId::new();
    let written = note(&reader, &state, id, 1);
    assert_eq!(
        put(&srv, &format!("{}/{id}", notes(&state)), &reader, &written).await,
        StatusCode::OK
    );

    // Remove the leaver: a new epoch.
    let rotate = rotation(
        &owner,
        &state,
        vec![
            member(&owner, SharingRole::Editor),
            member(&reader, SharingRole::Reader),
        ],
    );
    let (code, body) = srv
        .post(
            &format!("{}/access", path(state.access.manifest.share_id)),
            Some(&owner.access),
            &rotate,
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let rotated: SharedItemState = serde_json::from_value(body).unwrap();
    assert_eq!(
        srv.get(&notes(&state), &leaver.access).await.0,
        StatusCode::NOT_FOUND
    );

    // Old-epoch notes stay readable to members with the old key set until rekeyed.
    let (_, p) = page(&srv, &rotated, &reader).await;
    assert_eq!(p.access_epoch, 2);
    assert_eq!(
        p.key_sets
            .iter()
            .map(|k| k.access_epoch)
            .collect::<Vec<_>>(),
        vec![1]
    );
    let rekey = RekeySharedNotesRequest {
        access_epoch: 2,
        notes: vec![RekeyedSharedNote {
            note_id: id,
            revision: 1,
            nonce: random::<24>().to_vec().into(),
            ciphertext: random::<300>().to_vec().into(),
        }],
    };
    let rekey_path = format!("{}/rekey", notes(&state));
    assert_eq!(
        srv.post(&rekey_path, Some(&owner.access), &rekey).await.0,
        StatusCode::CONFLICT,
        "no key yet"
    );
    assert_eq!(
        put(&srv, &keys, &owner, &key_set(&owner, &rotated)).await,
        StatusCode::CREATED
    );
    assert_eq!(
        srv.post(&rekey_path, Some(&reader.access), &rekey).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        srv.post(&rekey_path, Some(&owner.access), &rekey).await.0,
        StatusCode::NO_CONTENT
    );
    // Twice is refused: the note is already in the current epoch.
    assert_eq!(
        srv.post(&rekey_path, Some(&owner.access), &rekey).await.0,
        StatusCode::CONFLICT
    );
    let (_, p) = page(&srv, &rotated, &reader).await;
    let stored = &p.notes[0];
    assert_eq!((stored.access_epoch, stored.revision), (2, 1));
    assert_eq!(stored.signature, written.signature);
    assert_eq!(stored.payload_hash, written.payload_hash);
    assert_eq!(stored.ciphertext, rekey.notes[0].ciphertext);
    assert_eq!(
        p.key_sets
            .iter()
            .map(|k| k.access_epoch)
            .collect::<Vec<_>>(),
        vec![2]
    );

    // Writes must target the current epoch.
    let stale = note(&reader, &state, ObjectId::new(), 1);
    assert_eq!(
        put(
            &srv,
            &format!("{}/{}", notes(&state), stale.note_id),
            &reader,
            &stale
        )
        .await,
        StatusCode::CONFLICT
    );
}
