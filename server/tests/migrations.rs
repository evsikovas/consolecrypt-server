// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Schema migrations: forward-only, idempotent, upgrade with existing data,
//! and applied migrations never edited.

mod common;

use common::*;
use consolecrypt_server::db::MIGRATOR;
use uuid::Uuid;

/// SHA-384 checksums of released migrations. An applied migration must never
/// change (deployed databases would refuse to start): add a new file instead.
const RELEASED: &[(i64, &str)] = &[
    (1, "a48892d585965612abb818bf2e3f431698765eafa3409ab64899a519f51d9eab8107b59f3875134ec4853f27d219cc1f"),
    (2, "f420a99e9161b14b3df1f9fd4552ffd6940581cbaf7854c50ea9fd7126d7c0138c9cb46482a843021c4b2eb92446189b"),
    (3, "86bd88712ca73924d5acbe5f5cd8fc6f723b3145f7c82e4b618e49e060ed6f21b8f45358b6856213f74f8ce3bbd2ef1b"),
    (4, "6968bf58bf2020d851e9e6f663fcf54155c57ec840108b0363cb13dd22dc84b39b0cf71e114fae29e2d767289953b3cf"),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn released_migrations_are_immutable() {
    for (version, checksum) in RELEASED {
        let m = MIGRATOR
            .iter()
            .find(|m| m.version == *version)
            .unwrap_or_else(|| panic!("migration {version} missing"));
        assert_eq!(
            hex(&m.checksum),
            *checksum,
            "migration {version} was edited — never change a released migration, add a new one"
        );
    }
    let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    let mut sorted = versions.clone();
    sorted.sort();
    assert_eq!(versions, sorted);
}

#[tokio::test]
async fn migrations_are_idempotent() {
    let Some((db, _)) = TestDb::create().await else {
        return;
    };
    MIGRATOR.run(&db.pool).await.unwrap();
    MIGRATOR.run(&db.pool).await.unwrap();
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(applied as usize, MIGRATOR.iter().count());
}

#[tokio::test]
async fn upgrade_from_0001_keeps_data_and_backfills_epoch() {
    let Some((db, _)) = TestDb::create().await else {
        return;
    };
    MIGRATOR.run_to(1, &db.pool).await.unwrap();

    // A populated v0001 database.
    let (user, device, vault, object) = (
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
    );
    for (sql, binds) in [
        ("INSERT INTO users (id, email, password_hash) VALUES ($1, 'u@example.test', 'x')", vec![user]),
        ("INSERT INTO devices (id, user_id, name, platform, encryption_public_key, signing_public_key)
          VALUES ($1, $2, 'd', 'cli', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'))", vec![device, user]),
        ("INSERT INTO vaults (id, owner_user_id, access_key_verifier) VALUES ($1, $2, decode(repeat('03', 32), 'hex'))", vec![vault, user]),
        ("INSERT INTO vault_sequences (vault_id, last_sequence) VALUES ($1, 1)", vec![vault]),
        ("INSERT INTO vault_objects (vault_id, object_id, revision, sequence, format, ciphertext, nonce, wrapped_dek, wrapped_dek_nonce, writer_device_id)
          VALUES ($1, $2, 1, 1, 1, decode('abcd', 'hex'), decode(repeat('04', 24), 'hex'), decode(repeat('05', 48), 'hex'), decode(repeat('06', 24), 'hex'), $3)", vec![vault, object, device]),
    ] {
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        q.execute(&db.pool).await.unwrap();
    }

    MIGRATOR.run(&db.pool).await.unwrap();

    let epoch: Option<Uuid> = sqlx::query_scalar("SELECT epoch FROM vaults WHERE id = $1")
        .bind(vault)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(epoch.is_some());
    let ciphertext: Vec<u8> =
        sqlx::query_scalar("SELECT ciphertext FROM vault_objects WHERE object_id = $1")
            .bind(object)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(ciphertext, vec![0xab, 0xcd]);
}
