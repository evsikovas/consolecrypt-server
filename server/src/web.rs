// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Embedded public website. Exact routes deliberately leave unknown API paths
//! to the JSON 404 handler; no SPA rewrite can mask a protocol error.
use crate::AppState;
use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::Response,
    routing::get,
    Router,
};

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";

fn page(body: &'static [u8], content_type: &'static str) -> Response {
    let mut response = Response::new(Body::from(body));
    let h = response.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    response
}

pub fn router() -> Router<AppState> {
    macro_rules! asset {
        ($file:literal, $mime:literal) => {
            get(|| async { page(include_bytes!(concat!("../web/", $file)), $mime) })
        };
    }
    Router::new()
        .route("/", asset!("index.html", "text/html; charset=utf-8"))
        .route(
            "/account",
            asset!("account.html", "text/html; charset=utf-8"),
        )
        .route(
            "/privacy",
            asset!("privacy.html", "text/html; charset=utf-8"),
        )
        .route(
            "/assets/site.css",
            asset!("assets/site.css", "text/css; charset=utf-8"),
        )
        .route(
            "/assets/site.js",
            asset!("assets/site.js", "text/javascript; charset=utf-8"),
        )
        .route(
            "/assets/api.js",
            asset!("assets/api.js", "text/javascript; charset=utf-8"),
        )
        .route(
            "/assets/account.js",
            asset!("assets/account.js", "text/javascript; charset=utf-8"),
        )
        .route(
            "/assets/mark.svg",
            asset!("assets/mark.svg", "image/svg+xml"),
        )
        .route(
            "/assets/desktop.png",
            asset!("assets/desktop.png", "image/png"),
        )
        .route("/assets/phone.png", asset!("assets/phone.png", "image/png"))
        .route(
            "/robots.txt",
            get(|| async {
                page(
                    b"User-agent: *\nDisallow: /account\nDisallow: /v1/\n",
                    "text/plain; charset=utf-8",
                )
            }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn website_allows_only_local_assets_and_retains_isolation() {
        let response = page(b"test", "text/html; charset=utf-8");
        let h = response.headers();
        assert_eq!(h[header::CONTENT_TYPE], "text/html; charset=utf-8");
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"));
    }
}
