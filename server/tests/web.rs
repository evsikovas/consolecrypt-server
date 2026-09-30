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
