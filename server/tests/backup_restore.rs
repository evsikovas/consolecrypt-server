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
    let original = server!();
    let a = original.new_account().await;
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
    let restored = TestServer::spawn_on(restored_db, url, |_| {}).await;

    // Same account, same device, same session material, same ciphertext.
    let (s, body) = restored.login(&a.email, &a.password, &a.device).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let session = restored.session(a.email.clone(), a.password.clone(), a.device, body);
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
