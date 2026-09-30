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

/// A released-schema personal vault, with opaque random bytes rather than
/// usable fixture keys. Returned identifiers are public metadata only.
async fn seed_personal_vault(pool: &sqlx::PgPool) -> (Uuid, Uuid, Uuid) {
    let (user, device, vault) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)")
        .bind(user)
        .bind(random_email())
        .bind("unused-migration-test-password-hash")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, user_id, name, platform, encryption_public_key, signing_public_key)
         VALUES ($1, $2, 'migration device', 'cli', $3, $4)",
    )
    .bind(device)
    .bind(user)
    .bind(random::<32>().as_slice())
    .bind(random::<32>().as_slice())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vaults (id, owner_user_id, created_by_device_id, access_key_verifier)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(vault)
    .bind(user)
    .bind(device)
    .bind(random::<32>().as_slice())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO vault_members (vault_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(vault)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO vault_sequences (vault_id, last_sequence, stored_bytes) VALUES ($1, 1, 48)",
    )
    .bind(vault)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vault_key_envelopes
           (id, vault_id, recipient_type, recipient_id, kind, algorithm, metadata,
            ciphertext, nonce, created_by_device_id)
         VALUES ($1, $2, 'device', $3, 'vrk_v1', 'migration-test', '{}', $4, $5, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(vault)
    .bind(device)
    .bind(random::<48>().as_slice())
    .bind(random::<24>().as_slice())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vault_objects
           (vault_id, object_id, revision, sequence, format, ciphertext, nonce,
            wrapped_dek, wrapped_dek_nonce, writer_device_id)
         VALUES ($1, $2, 1, 1, 1, $3, $4, $5, $6, $7)",
    )
    .bind(vault)
    .bind(Uuid::now_v7())
    .bind(random::<48>().as_slice())
    .bind(random::<24>().as_slice())
    .bind(random::<48>().as_slice())
    .bind(random::<24>().as_slice())
    .bind(device)
    .execute(pool)
    .await
    .unwrap();
    (user, device, vault)
}

/// Compare whole rows, including timestamps and opaque payloads. Callers use
/// assert!(a == b), so a failure never dumps envelopes/ciphertext to test logs.
async fn personal_snapshot(pool: &sqlx::PgPool) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
           'users', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM users t),
           'devices', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM devices t),
           'vaults', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM vaults t),
           'members', (SELECT jsonb_agg(to_jsonb(t) ORDER BY vault_id, user_id) FROM vault_members t),
           'sequences', (SELECT jsonb_agg(to_jsonb(t) ORDER BY vault_id) FROM vault_sequences t),
           'envelopes', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM vault_key_envelopes t),
           'objects', (SELECT jsonb_agg(to_jsonb(t) ORDER BY vault_id, object_id) FROM vault_objects t)
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn upgrade_from_0004_preserves_personal_vault_and_sharing_instance() {
    let Some((db, _)) = TestDb::create().await else {
        return;
    };
    MIGRATOR.run_to(4, &db.pool).await.unwrap();
    seed_personal_vault(&db.pool).await;
    let before = personal_snapshot(&db.pool).await;

    MIGRATOR.run(&db.pool).await.unwrap();
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM sharing_instance")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(!instance.is_nil());
    let sharing_rows: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM shared_items),
                (SELECT count(*) FROM shared_manifests),
                (SELECT count(*) FROM shared_item_devices)",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        sharing_rows,
        (0, 0, 0),
        "personal vaults must not become shared"
    );

    MIGRATOR.run(&db.pool).await.unwrap();
    MIGRATOR.run(&db.pool).await.unwrap();
    let instances: Vec<Uuid> = sqlx::query_scalar("SELECT instance_id FROM sharing_instance")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!(instances, vec![instance]);
    assert!(
        before == personal_snapshot(&db.pool).await,
        "upgrade or repeated migration changed personal data"
    );
}

#[tokio::test]
async fn sharing_and_personal_vaults_have_independent_namespaces_and_lifetimes() {
    let Some((db, _)) = TestDb::create().await else {
        return;
    };
    MIGRATOR.run(&db.pool).await.unwrap();
    let (user, device, vault) = seed_personal_vault(&db.pool).await;
    let before = personal_snapshot(&db.pool).await;

    // Reuse the vault UUID deliberately: neither namespace references the
    // other's membership, encrypted objects, envelopes or deletion cascade.
    for round in 0..2 {
        sqlx::query(
            "INSERT INTO shared_items
               (id, owner_user_id, owner_device_id, revision, access_epoch, manifest_revision,
                manifest_hash, revision_hash, current_manifest, current_mutation)
             VALUES ($1, $2, $3, 1, 1, 1, $4, $5, '{}', '{}')",
        )
        .bind(vault)
        .bind(user)
        .bind(device)
        .bind(random::<32>().as_slice())
        .bind(random::<32>().as_slice())
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO shared_manifests (share_id, manifest_revision, manifest_hash, document)
             VALUES ($1, 1, $2, '{}')",
        )
        .bind(vault)
        .bind(random::<32>().as_slice())
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO shared_item_devices (share_id, device_id, user_id, role)
             VALUES ($1, $2, $3, 'read')",
        )
        .bind(vault)
        .bind(device)
        .bind(user)
        .execute(&db.pool)
        .await
        .unwrap();
        assert!(
            before == personal_snapshot(&db.pool).await,
            "sharing writes changed personal data or trust"
        );
        if round == 0 {
            sqlx::query("DELETE FROM shared_items WHERE id = $1")
                .bind(vault)
                .execute(&db.pool)
                .await
                .unwrap();
            let children: i64 = sqlx::query_scalar(
                "SELECT (SELECT count(*) FROM shared_manifests) +
                        (SELECT count(*) FROM shared_item_devices)",
            )
            .fetch_one(&db.pool)
            .await
            .unwrap();
            assert_eq!(children, 0);
            assert!(
                before == personal_snapshot(&db.pool).await,
                "sharing deletion changed personal data"
            );
        }
    }

    sqlx::query("DELETE FROM vaults WHERE id = $1")
        .bind(vault)
        .execute(&db.pool)
        .await
        .unwrap();
    let remaining: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM shared_items),
                (SELECT count(*) FROM shared_manifests),
                (SELECT count(*) FROM shared_item_devices)",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(remaining, (1, 1, 1));
}

#[tokio::test]
async fn reserved_migration_gap_can_be_filled_after_sharing_upgrade() {
    use sqlx::migrate::{Migration, MigrationType, Migrator};
    use sqlx::SqlSafeStr as _;

    let Some((db, _)) = TestDb::create().await else {
        return;
    };
    // Exercise sqlx's ordering with a harmless stand-in, not ADR-0007 SQL.
    // Explicitly omit 5 so this regression test remains meaningful once the
    // real reserved migration is eventually added to the release.
    let mut migrations: Vec<_> = MIGRATOR
        .iter()
        .filter(|m| m.version != 5)
        .cloned()
        .collect();
    Migrator::with_migrations(migrations.clone())
        .run(&db.pool)
        .await
        .unwrap();
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM sharing_instance")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    migrations.push(Migration::new(
        5,
        "test reserved migration gap".into(),
        MigrationType::Simple,
        "CREATE TABLE migration_gap_probe (singleton boolean PRIMARY KEY CHECK (singleton));
         INSERT INTO migration_gap_probe (singleton) VALUES (true);"
            .into_sql_str(),
        false,
    ));
    let with_gap_filled = Migrator::with_migrations(migrations);
    with_gap_filled.run(&db.pool).await.unwrap();
    with_gap_filled.run(&db.pool).await.unwrap();
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(&db.pool)
            .await
            .unwrap();
    assert!(applied.contains(&5) && applied.contains(&6));
    let probe_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM migration_gap_probe")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(probe_rows, 1);
    let current_instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM sharing_instance")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(current_instance, instance);
}

#[tokio::test]
async fn enrollment_upgrade_preserves_existing_rows_and_has_share_scoped_cascades() {
    let Some((db, _)) = TestDb::create().await else {
        return;
    };
    MIGRATOR.run_to(6, &db.pool).await.unwrap();
    let (user, device, share) = seed_personal_vault(&db.pool).await;
    sqlx::query("INSERT INTO shared_items (id,owner_user_id,owner_device_id,revision,
        access_epoch,manifest_revision,manifest_hash,revision_hash,current_manifest,current_mutation)
        VALUES ($1,$2,$3,1,1,1,$4,$5,'{}','{}')")
        .bind(share).bind(user).bind(device).bind(random::<32>().as_slice())
        .bind(random::<32>().as_slice()).execute(&db.pool).await.unwrap();
    let before_personal = personal_snapshot(&db.pool).await;
    let before_shared: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM shared_items t WHERE id=$1")
            .bind(share)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM sharing_instance")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    MIGRATOR.run(&db.pool).await.unwrap();
    MIGRATOR.run(&db.pool).await.unwrap();
    let after_shared: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM shared_items t WHERE id=$1")
            .bind(share)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(
        before_shared == after_shared,
        "enrollment migration altered shared data"
    );
    assert!(
        before_personal == personal_snapshot(&db.pool).await,
        "enrollment migration altered personal data"
    );
    let after_instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM sharing_instance")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(after_instance, instance);

    // Schema-level opaque placeholders only. Deliberately absent anchor/target
    // IDs prove historical evidence does not depend on device-row retention.
    let grant = Uuid::now_v7();
    let request = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO shared_enrollment_grants (share_id,grant_id,revision,state_hash,
        access_manifest_hash,not_before,anchor_user_id,anchor_device_id,status,expires_at,document)
        VALUES ($1,$2,1,$3,$4,1,$5,$6,'active',2,'{}')",
    )
    .bind(share)
    .bind(grant)
    .bind(random::<32>().as_slice())
    .bind(random::<32>().as_slice())
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO shared_enrollment_grant_states (share_id,grant_id,revision,state_hash,document)
        VALUES ($1,$2,1,$3,'{}')").bind(share).bind(grant).bind(random::<32>().as_slice())
        .execute(&db.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO shared_enrollment_requests (share_id,request_id,grant_id,
        grant_state_hash,request_hash,nonce,target_user_id,target_device_id,expires_at,document)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,2,'{}')",
    )
    .bind(share)
    .bind(request)
    .bind(grant)
    .bind(random::<32>().as_slice())
    .bind(random::<32>().as_slice())
    .bind(random::<32>().as_slice())
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO shared_enrollment_challenges (share_id,request_id,generation,
        challenge_id,ephemeral_public_key,nonce,ciphertext_hash) VALUES ($1,$2,1,$3,$4,$5,$6)",
    )
    .bind(share)
    .bind(request)
    .bind(Uuid::now_v7())
    .bind(random::<32>().as_slice())
    .bind(random::<24>().as_slice())
    .bind(random::<32>().as_slice())
    .execute(&db.pool)
    .await
    .unwrap();
    MIGRATOR.run(&db.pool).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM shared_enrollment_requests")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DELETE FROM shared_items WHERE id=$1")
        .bind(share)
        .execute(&db.pool)
        .await
        .unwrap();
    let children:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM shared_enrollment_grants)
        +(SELECT count(*) FROM shared_enrollment_grant_states)+(SELECT count(*) FROM shared_enrollment_requests)
        +(SELECT count(*) FROM shared_enrollment_challenges)").fetch_one(&db.pool).await.unwrap();
    assert_eq!(children, 0);
    assert!(
        before_personal == personal_snapshot(&db.pool).await,
        "sharing cascade altered personal data"
    );
}
