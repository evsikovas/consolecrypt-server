// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Coarse performance guard: a full 500-mutation push and a 1000-item pull
//! must stay well below client timeouts (debug build, local PostgreSQL).

mod common;

use cc_protocol::ObjectId;
use common::*;
use reqwest::StatusCode;
use std::time::{Duration, Instant};

#[tokio::test]
async fn max_batch_push_and_pull_are_fast_enough() {
    let srv = server!();
    let a = srv.new_account().await;
    let vault = srv.create_vault(&a).await;
    let batch: Vec<_> = (0..cc_protocol::limits::MAX_PUSH_BATCH)
        .map(|_| put(ObjectId::new(), 0))
        .collect();
    let started = Instant::now();
    let (status, _) = srv.push(&a, vault.id, batch).await;
    let push = started.elapsed();
    assert_eq!(status, StatusCode::OK);

    let started = Instant::now();
    let (status, body) = srv
        .get(
            &format!(
                "{}?vault_id={}&after=0&limit=1000",
                cc_protocol::paths::SYNC_CHANGES,
                vault.id
            ),
            &a.access,
        )
        .await;
    let pull = started.elapsed();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changes"].as_array().unwrap().len(), 500);
    eprintln!("push 500: {push:?}, pull 500: {pull:?}");
    assert!(push < Duration::from_secs(10), "push took {push:?}");
    assert!(pull < Duration::from_secs(5), "pull took {pull:?}");
}
