// SPDX-License-Identifier: AGPL-3.0-only
mod common;

#[tokio::test]
async fn web_routes_have_local_asset_csp_and_do_not_mask_api_errors() {
    let srv = server!();
    for (path, content_type) in [
        ("/", "text/html"),
        ("/account", "text/html"),
        ("/privacy", "text/html"),
        ("/assets/api.js", "text/javascript"),
        ("/assets/i18n.js", "text/javascript"),
        ("/assets/en.js", "text/javascript"),
        ("/assets/site.css", "text/css"),
        ("/assets/desktop.png", "image/png"),
        ("/assets/phone.png", "image/png"),
    ] {
        let response = srv.http.get(srv.url(path)).send().await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert!(response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with(content_type));
        assert!(response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'"));
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(!response.bytes().await.unwrap().is_empty());
    }
    let response = srv
        .http
        .get(srv.url("/v1/does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert_eq!(response.headers()["content-type"], "application/json");
    let response = srv
        .http
        .get(srv.url("/v1/auth/me"))
        .header("x-cc-protocol-version", "1.5")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
}
