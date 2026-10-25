// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Built-in account page (`GET /account`, opt-in with `CC_WEB_ACCOUNT=true`):
//! lets people confirm their email, set a new account password with the
//! single-use codes the server mails and answer "This wasn't me" links,
//! without a separate website. A self-hosted server points `CC_PUBLIC_URL`
//! at itself and mail gets a button to this page. Off by default: the
//! server stays API-only and the operator's website serves `/account`.
//!
//! The page is static and embedded in the binary. It uses only the public,
//! code-based API (`/v1/auth/email/verify`, `/v1/auth/password/{forgot,reset}`,
//! `/v1/recovery/account/confirm`, `/v1/devices/deny`) of the same origin: no
//! login, no cookies, no vault access. Codes arrive in the URL fragment,
//! which browsers never send to the server, so they cannot reach access logs.

use crate::config::MailLanguage;
use crate::state::AppState;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

const INDEX_HTML: &str = include_str!("web/account/index.html");
const APP_JS: &str = include_str!("web/account/app.js");
const APP_CSS: &str = include_str!("web/account/app.css");

/// Same-origin only; no inline script or style, no framing, no form posts
/// (forms are handled by the script), no third-party anything.
pub const ACCOUNT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'; \
     frame-ancestors 'none'";

pub const ACCOUNT_PATH: &str = "/account";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(ACCOUNT_PATH, get(index))
        .route("/account/", get(index))
        .route("/account/app.js", get(app_js))
        .route("/account/app.css", get(app_css))
}

fn page(content_type: &'static str, body: String) -> Response {
    (
        [
            (CONTENT_TYPE, content_type),
            (CONTENT_SECURITY_POLICY, ACCOUNT_CSP),
            (CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn index(State(state): State<AppState>) -> Response {
    let lang = match state.config.mail.language {
        MailLanguage::Ru => "ru",
        MailLanguage::En => "en",
    };
    page(
        "text/html; charset=utf-8",
        INDEX_HTML.replace("{{LANG}}", lang),
    )
}

async fn app_js() -> Response {
    page("text/javascript; charset=utf-8", APP_JS.to_owned())
}

async fn app_css() -> Response {
    page("text/css; charset=utf-8", APP_CSS.to_owned())
}
