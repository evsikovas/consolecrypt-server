// SPDX-License-Identifier: AGPL-3.0-only
mod common;

#[tokio::test]
async fn server_is_api_only_and_does_not_serve_website_assets() {
    let srv = server!();
    for path in [
        "/",
        "/account",
        "/privacy",
        "/assets/api.js",
        "/assets/site.css",
        "/v1/does-not-exist",
    ] {
        let response = srv.http.get(srv.url(path)).send().await.unwrap();
        assert_eq!(response.status(), 404, "{path}");
        assert_eq!(
            response.headers()["content-type"],
            "application/json",
            "{path}"
        );
        assert!(response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'"));
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["code"], "not_found", "{path}");
    }
    assert_eq!(
        srv.http
            .get(srv.url("/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        srv.http
            .get(srv.url("/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let response = srv.http.get(srv.url("/v1/meta")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let meta: serde_json::Value = response.json().await.unwrap();
    assert_eq!(meta["server_version"], env!("CARGO_PKG_VERSION"));
    let response = srv.http.get(srv.url("/v1/auth/me")).send().await.unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn opt_in_account_page_is_served_with_a_strict_csp() {
    let srv = server!(|c| c.web_account = true);
    let resp = srv.http.get(srv.url("/account")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let h = resp.headers().clone();
    assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
    assert_eq!(
        h["content-security-policy"],
        consolecrypt_server::web::ACCOUNT_CSP
    );
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cache-control"], "no-store");
    let body = resp.text().await.unwrap();
    assert!(body.contains("<html lang=\"ru\">"));
    assert!(body.contains("/account/app.js"));
    assert!(
        !body.contains("<script>"),
        "no inline script (CSP forbids it)"
    );

    for (path, ct) in [
        ("/account/", "text/html"),
        ("/account/app.js", "text/javascript"),
        ("/account/app.css", "text/css"),
    ] {
        let resp = srv.http.get(srv.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        assert!(resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with(ct));
    }
    let script = srv
        .http
        .get(srv.url("/account/app.js"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for endpoint in [
        cc_protocol::paths::AUTH_EMAIL_VERIFY,
        cc_protocol::paths::AUTH_PASSWORD_FORGOT,
        cc_protocol::paths::AUTH_PASSWORD_RESET,
        cc_protocol::paths::RECOVERY_ACCOUNT_CONFIRM,
        cc_protocol::paths::DEVICES_DENY,
    ] {
        assert!(script.contains(endpoint), "{endpoint}");
    }
    // Nothing else becomes a website, and API responses keep the deny-all policy.
    for path in ["/", "/account/other", "/accounts"] {
        let resp = srv.http.get(srv.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), 404, "{path}");
    }
    let resp = srv.http.get(srv.url("/v1/meta")).send().await.unwrap();
    assert_eq!(
        resp.headers()["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );
}

#[tokio::test]
async fn account_page_follows_the_mail_language() {
    let srv = server!(|c| {
        c.web_account = true;
        c.mail.language = consolecrypt_server::config::MailLanguage::En;
    });
    let body = srv
        .http
        .get(srv.url("/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<html lang=\"en\">"));
}

#[tokio::test]
async fn email_link_points_at_the_account_page_and_its_code_works() {
    let srv = server!(|c| {
        c.web_account = true;
        c.require_email_verification = true;
        c.public_url = Some("https://sync.example.org".into());
    });
    let a = srv.new_account().await;
    srv.mailer
        .wait_for(consolecrypt_server::mail::MailKind::VerifyEmail, 1)
        .await;
    let body = srv
        .mailer
        .messages
        .lock()
        .unwrap()
        .iter()
        .find(|(k, to, _)| *k == consolecrypt_server::mail::MailKind::VerifyEmail && *to == a.email)
        .map(|(_, _, body)| body.clone())
        .unwrap();
    // The link targets the account page; the code sits in the fragment.
    let link = body
        .lines()
        .find(|l| l.starts_with("https://sync.example.org/account#"))
        .expect("account link in the email")
        .to_owned();
    assert!(link.contains("#action=verify&token=cct_"));
    assert!(!body.contains("кабинет"));
    let token = link.split("token=").nth(1).unwrap();
    assert!(
        body.lines().any(|l| l == token),
        "the code is on its own line too"
    );

    // What the page does with it: the public, code-based endpoint.
    let (s, _) = srv
        .post(
            cc_protocol::paths::AUTH_EMAIL_VERIFY,
            None,
            &serde_json::json!({ "token": token }),
        )
        .await;
    assert_eq!(s, 204);
    let (s, me) = srv.get(cc_protocol::paths::AUTH_ME, &a.access).await;
    assert_eq!(s, 200);
    assert_eq!(me["email_verified"], true);
}
