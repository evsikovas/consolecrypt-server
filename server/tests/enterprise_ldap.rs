// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Enterprise LDAP / Active Directory sign-in against a real Samba AD DC
//! (`tests/stands`, container `cc-test-samba`). Env-gated: runs only with
//! `CC_TEST_SAMBA=1` (see `tests/stands/README.md`), plus the usual
//! `CC_TEST_DATABASE_URL`. Users that tests change are created per test
//! (`samba-tool` via `docker exec`) and removed afterwards.

mod common;

use common::enterprise::SecretDir;
use common::{TestDevice, TestServer};
use consolecrypt_server::config::{AuthConfig, AuthModeKind, LdapConfig, ProviderKind};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone)]
struct Samba {
    ldaps_url: String,
    ldap_url: String,
    ca_file: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    group_dn: String,
    user_password: String,
    container: String,
}

fn samba() -> Option<Samba> {
    if std::env::var("CC_TEST_SAMBA").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping Samba AD test: run tests/stands/stands.py up samba and set CC_TEST_SAMBA=1"
        );
        return None;
    }
    let v = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is required"));
    Some(Samba {
        ldaps_url: v("CC_TEST_SAMBA_LDAPS_URL"),
        ldap_url: v("CC_TEST_SAMBA_LDAP_URL"),
        ca_file: v("CC_TEST_SAMBA_CA_FILE"),
        bind_dn: v("CC_TEST_SAMBA_BIND_DN"),
        bind_password: v("CC_TEST_SAMBA_BIND_PASSWORD"),
        base_dn: v("CC_TEST_SAMBA_BASE_DN"),
        group_dn: v("CC_TEST_SAMBA_GROUP_DN"),
        user_password: v("CC_TEST_SAMBA_USER_PASSWORD"),
        container: std::env::var("CC_TEST_SAMBA_CONTAINER")
            .unwrap_or_else(|_| "cc-test-samba".into()),
    })
}

impl Samba {
    fn ldap_config(&self, dir: &SecretDir, starttls: bool) -> LdapConfig {
        LdapConfig {
            url: if starttls {
                self.ldap_url.clone()
            } else {
                self.ldaps_url.clone()
            },
            starttls,
            ca_file: Some(self.ca_file.clone().into()),
            bind_dn: self.bind_dn.clone(),
            bind_password_file: dir.write(
                "bind-password",
                format!("{}\n", self.bind_password).as_bytes(),
            ),
            base_dn: self.base_dn.clone(),
            user_filter: consolecrypt_server::config::DEFAULT_LDAP_USER_FILTER.into(),
            email_attr: "mail".into(),
            id_attr: "objectGUID".into(),
            required_group: Some(self.group_dn.clone()),
            timeout: Duration::from_secs(10),
            max_failures: 3,
            failure_window: Duration::from_secs(900),
            max_failures_per_ip: 0,
        }
    }

    fn configure(&self, dir: &SecretDir, starttls: bool, c: &mut consolecrypt_server::Config) {
        c.auth = AuthConfig {
            mode: AuthModeKind::Enterprise,
            provider: Some(ProviderKind::Ldap),
            display_name: Some("CCTEST".into()),
            allowed_domains: vec!["acme.test".into()],
            ldap: Some(self.ldap_config(dir, starttls)),
            ..AuthConfig::standard()
        };
    }

    fn tool(&self, args: &[&str]) {
        let out = std::process::Command::new("docker")
            .args([
                "--context",
                "orbstack",
                "exec",
                &self.container,
                "samba-tool",
            ])
            .args(args)
            .output()
            .expect("docker exec");
        assert!(
            out.status.success(),
            "samba-tool {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A per-test user in the ConsoleCrypt group; returns its name.
    fn create_user(&self) -> String {
        let name = format!("t{}", &uuid::Uuid::now_v7().simple().to_string()[16..]);
        self.tool(&[
            "user",
            "create",
            &name,
            &self.user_password,
            &format!("--mail-address={name}@acme.test"),
            "--use-username-as-cn",
        ]);
        self.tool(&["group", "addmembers", "ConsoleCrypt", &name]);
        name
    }

    fn delete_user(&self, name: &str) {
        let _ = std::process::Command::new("docker")
            .args([
                "--context",
                "orbstack",
                "exec",
                &self.container,
                "samba-tool",
                "user",
                "delete",
                name,
            ])
            .output();
    }
}

macro_rules! ldap_server {
    ($s:expr, $dir:expr, $starttls:expr) => {
        ldap_server!(
            $s,
            $dir,
            $starttls,
            |_c: &mut consolecrypt_server::Config| {}
        )
    };
    ($s:expr, $dir:expr, $starttls:expr, $extra:expr) => {{
        let s = &$s;
        let dir = &$dir;
        let extra = $extra;
        match TestServer::spawn(|c| {
            s.configure(dir, $starttls, c);
            extra(c);
        })
        .await
        {
            Some(srv) => srv,
            None => return,
        }
    }};
}

async fn ldap_login(
    srv: &TestServer,
    login: &str,
    password: &str,
    device: &TestDevice,
) -> (StatusCode, Value) {
    srv.post(
        cc_protocol::paths::AUTH_LDAP_LOGIN,
        None,
        &json!({
            "login": login,
            "password": password,
            "device": device.registration(),
            "device_proof": device.proof(),
        }),
    )
    .await
}

#[tokio::test]
async fn ldaps_login_creates_account_repeat_and_second_device() {
    let Some(s) = samba() else { return };
    let dir = SecretDir::new();
    let srv = ldap_server!(s, dir, false);
    let (_, meta) = srv.get(cc_protocol::paths::META, "").await;
    assert_eq!(
        meta["capabilities"]["auth"],
        json!({"mode": "enterprise", "provider": "ldap", "display_name": "CCTEST"})
    );

    let laptop = TestDevice::new("Laptop");
    let (status, first) = ldap_login(&srv, "alice@acme.test", &s.user_password, &laptop).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let user_id = first["user_id"].as_str().unwrap().to_owned();
    let (subject, email): (String, String) = sqlx::query_as(
        "SELECT i.subject, u.email FROM account_identities i JOIN users u ON u.id = i.account_id
          WHERE i.account_id = $1::uuid AND i.provider = 'ldap'",
    )
    .bind(&user_id)
    .fetch_one(&srv.state.db)
    .await
    .unwrap();
    assert_eq!(email, "alice@acme.test");
    assert!(
        consolecrypt_server::enterprise::ldap::parse_guid(&subject).is_some(),
        "objectGUID: {subject}"
    );

    // Same person via UPN and DOMAIN\user: same account.
    for login in ["alice@cctest.local", "CCTEST\\alice", "alice"] {
        let (status, body) = ldap_login(&srv, login, &s.user_password, &laptop).await;
        assert_eq!(status, StatusCode::OK, "{login}: {body}");
        assert_eq!(body["user_id"], user_id.as_str(), "{login}");
    }
    let phone = TestDevice::new("Phone");
    let (status, body) = ldap_login(&srv, "alice@acme.test", &s.user_password, &phone).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], user_id.as_str());
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM devices").await, 2);

    // Nested group membership counts.
    let (status, body) = ldap_login(
        &srv,
        "nina@acme.test",
        &s.user_password,
        &TestDevice::new("n"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Admin trial sign-in.
    let lines = consolecrypt_server::admin::auth_test(
        &srv.state.db,
        &srv.state.config,
        Some("alice@acme.test"),
        Some(cc_protocol::auth::SecretString::new(
            s.user_password.clone(),
        )),
    )
    .await
    .unwrap();
    assert!(lines.iter().any(|l| l.contains("accepted")), "{lines:?}");
    let status_lines = consolecrypt_server::admin::auth_status(&srv.state.db, &srv.state.config)
        .await
        .unwrap();
    assert!(
        status_lines.iter().any(|l| l.contains("OK")),
        "{status_lines:?}"
    );
}

#[tokio::test]
async fn starttls_login_works() {
    let Some(s) = samba() else { return };
    let dir = SecretDir::new();
    let srv = ldap_server!(s, dir, true);
    let (status, body) = ldap_login(
        &srv,
        "alice@acme.test",
        &s.user_password,
        &TestDevice::new("x"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn wrong_password_unknown_user_disabled_and_no_group_are_refused() {
    let Some(s) = samba() else { return };
    let dir = SecretDir::new();
    let srv = ldap_server!(s, dir, false);
    let dev = TestDevice::new("x");
    let (status, wrong) = ldap_login(&srv, "nina@acme.test", "Wrong-Password-1!", &dev).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, unknown) = ldap_login(&srv, "nobody@acme.test", "Wrong-Password-1!", &dev).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Identical answers (request ids aside).
    assert_eq!(wrong["code"], unknown["code"]);
    assert_eq!(wrong["message"], unknown["message"]);
    assert_eq!(wrong["code"], "invalid_credentials");
    // Empty password never becomes an anonymous bind.
    let (status, _) = ldap_login(&srv, "nina@acme.test", "", &dev).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Filter injection does not match anybody.
    let (status, _) = ldap_login(&srv, "*", &s.user_password, &dev).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Disabled AD account (dave): the directory refuses the bind.
    let (status, body) = ldap_login(&srv, "dave@acme.test", &s.user_password, &dev).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || body["code"] == "account_disabled",
        "{status} {body}"
    );
    // Not in the required group.
    let (status, body) = ldap_login(&srv, "bob@acme.test", &s.user_password, &dev).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "group_required");
    assert_eq!(srv.db_scalar_i64("SELECT count(*) FROM users").await, 0);
    let refusals = srv
        .db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'login_failed'
               AND metadata->>'method' = 'ldap'",
        )
        .await;
    assert!(refusals >= 5, "{refusals}");
}

#[tokio::test]
async fn lockout_guard_stops_before_the_directory_counts_failures() {
    let Some(s) = samba() else { return };
    let dir = SecretDir::new();
    let srv = ldap_server!(s, dir, false);
    let name = s.create_user();
    let dev = TestDevice::new("x");
    let login = format!("{name}@acme.test");
    for i in 0..3 {
        let (status, body) = ldap_login(&srv, &login, "Wrong-Password-1!", &dev).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}: {body}");
    }
    // Budget spent: refused without a bind, even with the right password.
    let (status, body) = ldap_login(&srv, &login, &s.user_password, &dev).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "rate_limited");
    assert!(body["retry_after_seconds"].as_u64().unwrap() > 0);
    // Another spelling of the same directory user is covered too.
    let (status, _) = ldap_login(&srv, &name, &s.user_password, &dev).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Unknown logins behave the same way (no enumeration).
    let ghost = format!("ghost{}@acme.test", uuid::Uuid::now_v7().simple());
    for _ in 0..3 {
        let (status, _) = ldap_login(&srv, &ghost, "Wrong-Password-1!", &dev).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = ldap_login(&srv, &ghost, "Wrong-Password-1!", &dev).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // The directory saw at most 3 failed binds (badPwdCount).
    let out = std::process::Command::new("docker")
        .args([
            "--context",
            "orbstack",
            "exec",
            &s.container,
            "ldbsearch",
            "-H",
            "/var/lib/samba/private/sam.ldb",
            &format!("(sAMAccountName={name})"),
            "badPwdCount",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    if let Some(n) = text
        .lines()
        .find_map(|l| l.strip_prefix("badPwdCount: "))
        .and_then(|v| v.trim().parse::<u32>().ok())
    {
        assert!(n <= 3, "badPwdCount {n}");
    }
    // After the window, a correct password works and resets the counters.
    sqlx::query("UPDATE ldap_login_failures SET window_start = now() - interval '16 minutes'")
        .execute(&srv.state.db)
        .await
        .unwrap();
    let (status, body) = ldap_login(&srv, &login, &s.user_password, &dev).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    s.delete_user(&name);
}

async fn refresh(srv: &TestServer, token: &str) -> (StatusCode, Value) {
    srv.post(
        cc_protocol::paths::AUTH_REFRESH,
        None,
        &json!({ "refresh_token": token }),
    )
    .await
}

#[tokio::test]
async fn recheck_revokes_disabled_removed_and_deleted_users() {
    let Some(s) = samba() else { return };
    let dir = SecretDir::new();
    let srv = ldap_server!(s, dir, false);
    let age = || async {
        sqlx::query("UPDATE account_identities SET checked_at = now() - interval '16 minutes'")
            .execute(&srv.state.db)
            .await
            .unwrap();
    };

    // Disabled in AD → refresh refused, sessions revoked.
    let name = s.create_user();
    let dev = TestDevice::new("x");
    let (status, body) =
        ldap_login(&srv, &format!("{name}@acme.test"), &s.user_password, &dev).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sess = srv.session(String::new(), String::new(), dev, body);
    let (status, ok) = refresh(&srv, &sess.refresh).await;
    assert_eq!(status, StatusCode::OK, "fresh: {ok}");
    age().await;
    let (status, ok) = refresh(&srv, ok["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "still enabled: {ok}");
    s.tool(&["user", "disable", &name]);
    age().await;
    let (status, err) = refresh(&srv, ok["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
    assert_eq!(err["code"], "account_disabled");
    s.delete_user(&name);

    // Removed from the group → the sweep revokes.
    let name = s.create_user();
    let dev = TestDevice::new("y");
    let (_, body) = ldap_login(&srv, &format!("{name}@acme.test"), &s.user_password, &dev).await;
    let sess = srv.session(String::new(), String::new(), dev, body);
    s.tool(&["group", "removemembers", "ConsoleCrypt", &name]);
    age().await;
    consolecrypt_server::enterprise::recheck::sweep_once(&srv.state)
        .await
        .unwrap();
    let (status, _) = srv.get(cc_protocol::paths::AUTH_ME, &sess.access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    s.delete_user(&name);

    // Deleted → the sweep revokes.
    let name = s.create_user();
    let dev = TestDevice::new("z");
    let (_, body) = ldap_login(&srv, &format!("{name}@acme.test"), &s.user_password, &dev).await;
    let sess = srv.session(String::new(), String::new(), dev, body);
    s.delete_user(&name);
    age().await;
    consolecrypt_server::enterprise::recheck::sweep_once(&srv.state)
        .await
        .unwrap();
    let (_, err) = refresh(&srv, &sess.refresh).await;
    assert_eq!(err["code"], "account_disabled");
    assert_eq!(
        srv.db_scalar_i64(
            "SELECT count(*) FROM audit_events WHERE event_type = 'enterprise_access_revoked'"
        )
        .await,
        3
    );
}

#[tokio::test]
async fn startup_validation_reports_tls_and_bind_problems() {
    let Some(s) = samba() else { return };
    let dir = SecretDir::new();
    let mut config = consolecrypt_server::Config::for_tests("postgres://unused/x");
    s.configure(&dir, false, &mut config);
    assert!(consolecrypt_server::enterprise::Enterprise::init(&config)
        .await
        .unwrap()
        .is_some());

    // Wrong service password.
    let mut bad = config.clone();
    let l = bad.auth.ldap.as_mut().unwrap();
    l.bind_password_file = dir.write("wrong", b"not-the-password");
    let err = consolecrypt_server::enterprise::Enterprise::init(&bad)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("service account bind"), "{err}");
    assert!(!err.contains("not-the-password"));

    // A CA file without certificates is refused.
    let mut bad = config.clone();
    let not_pem = dir.write("not-a-ca.pem", b"hello");
    bad.auth.ldap.as_mut().unwrap().ca_file = Some(not_pem);
    let err = consolecrypt_server::enterprise::Enterprise::init(&bad)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("CC_LDAP_CA_FILE"), "{err}");
    // System roots do not know the test CA: TLS verification fails.
    let mut bad = config.clone();
    bad.auth.ldap.as_mut().unwrap().ca_file = None;
    let err = consolecrypt_server::enterprise::Enterprise::init(&bad)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("cannot connect"), "{err}");

    // ldap:// without STARTTLS is refused at configuration time.
    let e = consolecrypt_server::Config::from_lookup(|k| match k {
        "CC_DATABASE_URL" => Some("postgres://x/y".into()),
        "CC_AUTH_MODE" => Some("enterprise".into()),
        "CC_AUTH_PROVIDER" => Some("ldap".into()),
        "CC_LDAP_URL" => Some(s.ldap_url.clone()),
        "CC_LDAP_BIND_DN" => Some(s.bind_dn.clone()),
        "CC_LDAP_BIND_PASSWORD_FILE" => Some("/x".into()),
        "CC_LDAP_BASE_DN" => Some(s.base_dn.clone()),
        _ => None,
    })
    .unwrap_err()
    .to_string();
    assert!(e.contains("plain ldap://"), "{e}");
}
