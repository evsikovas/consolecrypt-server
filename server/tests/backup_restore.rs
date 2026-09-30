// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! MVP acceptance 19: a PostgreSQL backup/restore does not break encrypted
//! vaults. Opt-in: needs PostgreSQL client tools matching the server version,
//! given as a command prefix, e.g.
//!
//!   CC_TEST_PG_TOOLS="docker exec -i cc-pg" CC_TEST_PG_USER=cc cargo test --test backup_restore
//!
//! (`pg_dump`/`pg_restore` run through that prefix and talk to the same
//! server as CC_TEST_DATABASE_URL.)

mod common;

use cc_protocol::sync::{ChangesResponse, MutationOp};
use cc_protocol::ObjectId;
use common::*;
use reqwest::StatusCode;
use std::io::Write as _;
use std::process::{Command, Stdio};

fn pg_tool(prefix: &str, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let mut parts = prefix.split_whitespace();
    let program = parts.next().expect("CC_TEST_PG_TOOLS is empty");
    let mut child = Command::new(program)
        .args(parts)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn pg tool");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{args:?} failed");
    out.stdout
}

#[tokio::test]
async fn restore_from_backup_keeps_vaults_usable() {
    let Ok(tools) = std::env::var("CC_TEST_PG_TOOLS") else {
        eprintln!("skipping: set CC_TEST_PG_TOOLS to run the backup/restore test");
        return;
    };
    let user = std::env::var("CC_TEST_PG_USER").unwrap_or_else(|_| "postgres".into());
    let original = server!(|c| {
        c.object_sharing_enabled = true;
        c.sharing_owner_online_enrollment_enabled = true;
    });
    let a = original.new_account().await;
    use cc_protocol::{sharing::SharingRole, sharing_enrollment::*};
    use common::enrollment as en;
    let anchor = original.new_account().await;
    let target = original
        .new_device_session(&anchor, "restored target")
        .await;
    let initial = common::sharing::create(&original, &a, &[(&anchor, SharingRole::Reader)]).await;
    let grant = en::grant(
        &a,
        &anchor,
        &initial,
        SharingRole::Reader,
        EnrollmentMode::Manual,
        2,
    );
    en::publish_grant(&original, &a, &grant).await;
    let submission = en::submission(&target, &anchor, &grant, SharingRole::Reader);
    let _: OwnDeviceRequestState = en::post(
        &original,
        &target,
        &en::requests_path(grant.grant.scope.share_id),
        &submission,
    )
    .await;
    let (challenge, response) = en::respond(&original, &a, &target, &submission).await;
    let acceptance = en::acceptance(
        &a,
        &target,
        &initial,
        &grant,
        &submission,
        &challenge,
        &response,
    );
    let request_path = en::request_path(
        grant.grant.scope.share_id,
        submission.request.request.request_id,
    );
    let accepted: OwnDeviceAcceptanceResult = en::post(
        &original,
        &a,
        &format!("{request_path}/accept"),
        &acceptance,
    )
    .await;
    let receipt_before: OwnDeviceRequestState = en::get(&original, &a, &request_path).await;
    let shared_before = accepted.state;
    let vault = original.create_vault(&a).await;
    let mutations: Vec<_> = (0..3).map(|_| put(ObjectId::new(), 0)).collect();
    let bodies: Vec<_> = mutations
        .iter()
        .map(|m| match &m.op {
            MutationOp::Put { body } => body.clone(),
            MutationOp::Delete => unreachable!(),
        })
        .collect();
    assert_eq!(
        original.push(&a, vault.id, mutations).await.0,
        StatusCode::OK
    );
    let (_, before) = original.changes(&a, vault.id, 0).await;
    let before: ChangesResponse = serde_json::from_value(before).unwrap();

    // Backup (custom format) and restore into a brand-new database.
    let dump = pg_tool(
        &tools,
        &["pg_dump", "-U", &user, "-Fc", original.db_name()],
        None,
    );
    let (restored_db, url) = TestDb::create().await.unwrap();
    pg_tool(
        &tools,
        &[
            "pg_restore",
            "-U",
            &user,
            "--no-owner",
            "-d",
            &restored_db.db_name,
        ],
        Some(&dump),
    );
    let restored = TestServer::spawn_on(restored_db, url, |c| {
        c.object_sharing_enabled = true;
        c.sharing_owner_online_enrollment_enabled = true;
    })
    .await;

    // Same account, same device, same session material, same ciphertext.
    let (s, body) = restored.login(&a.email, &a.password, &a.device).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let session = restored.session(a.email.clone(), a.password.clone(), a.device, body);
    let shared_after = consolecrypt_server::sharing::service::get(
        &restored.state,
        &common::sharing::context(&session),
        shared_before.access.manifest.share_id,
    )
    .await
    .unwrap();
    assert!(
        shared_after == shared_before,
        "restored sharing state changed"
    );
    let receipt_after: OwnDeviceRequestState = en::get(&restored, &session, &request_path).await;
    assert!(
        receipt_after == receipt_before,
        "restored accepted transcript changed"
    );
    // Receipt verification after a real restore must also work for the admitted
    // target, which is neither the owner nor the grant's original anchor.
    let (status, body) = restored
        .login(&target.email, &target.password, &target.device)
        .await;
    assert_eq!(status, StatusCode::OK);
    let target_session = restored.session(target.email, target.password, target.device, body);
    let target_receipt: OwnDeviceRequestState =
        en::get(&restored, &target_session, &request_path).await;
    assert!(
        target_receipt == receipt_before,
        "restored target receipt changed"
    );
    let head: SignedSharingOwnDevicesGrantState = en::get(
        &restored,
        &target_session,
        &en::grant_path(grant.grant.scope.share_id, grant.grant.grant_id),
    )
    .await;
    assert_eq!(
        en::grant_hash(&head),
        accepted.acceptance.acceptance.consumed_grant_successor_hash
    );
    let history: OwnDevicesGrantHistoryPage = en::get(
        &restored,
        &target_session,
        &format!(
            "{}/history",
            en::grant_path(grant.grant.scope.share_id, grant.grant.grant_id)
        ),
    )
    .await;
    assert!(
        history.states == vec![grant, accepted.consumed_grant_successor],
        "restored grant chain changed"
    );
    assert_eq!(
        restored
            .post(
                &format!("{request_path}/accept"),
                Some(&session.access),
                &acceptance
            )
            .await
            .0,
        StatusCode::CONFLICT,
        "restore must not permit replay"
    );
    assert_eq!(
        restored
            .db_scalar_i64("SELECT count(*) FROM shared_enrollment_challenges")
            .await,
        1
    );
    let caps = consolecrypt_server::sharing::service::capabilities(
        &restored.state,
        &common::sharing::context(&session),
    )
    .await
    .unwrap();
    assert_eq!(
        caps.server_instance_id,
        shared_before.access.manifest.server_instance_id
    );
    let (s, after) = restored.changes(&session, vault.id, 0).await;
    assert_eq!(s, StatusCode::OK);
    let after: ChangesResponse = serde_json::from_value(after).unwrap();
    assert_eq!(after.changes, before.changes);
    for (c, b) in after.changes.iter().zip(&bodies) {
        assert_eq!(c.body.as_ref().unwrap(), b);
    }
    // Sequences continue; epoch rotation after restore is visible.
    assert_eq!(
        restored
            .push(&session, vault.id, vec![put(ObjectId::new(), 0)])
            .await
            .1["latest_sequence"],
        4
    );
    consolecrypt_server::admin::rotate_epoch(&restored.state.db, None)
        .await
        .unwrap();
    let (_, now) = restored.changes(&session, vault.id, 0).await;
    assert_ne!(now["epoch"], serde_json::to_value(before.epoch).unwrap());
}
