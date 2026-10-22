// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `/v1/auth/oidc/{start,callback,exchange}` and `/v1/auth/ldap/login`
//! (protocol 1.8, see `cc_protocol::enterprise_auth`).
//!
//! `start` and `callback` are opened by the system browser: their own errors
//! are short plain-text pages; once the app's redirect URI is known, errors go
//! back to the app as `?error=<code>&error_description=…&state=…`.

use super::accounts::{self, audit_refusal, refuse};
use super::lockout::{self, Scope};
use super::oidc::UpstreamError;
use super::{token_context, Refusal, VerifiedIdentity};
use crate::config::ProviderKind;
use crate::crypto::{self, TokenKind};
use crate::devices;
use crate::error::{AppError, AppResult};
use crate::extract::{ApiJson, ClientIp};
use crate::state::AppState;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cc_protocol::auth::AuthResponse;
use cc_protocol::enterprise_auth::{
    callback_params, is_allowed_app_redirect_uri, is_valid_code_challenge, is_valid_code_verifier,
    LdapLoginRequest, OidcExchangeRequest, OidcStartQuery, CODE_CHALLENGE_METHOD_S256,
};
use cc_protocol::{limits, DeviceId, ErrorCode, UserId};
use serde::Deserialize;
use std::net::IpAddr;
use uuid::Uuid;

fn not_enabled(kind: ProviderKind) -> AppError {
    AppError::new(
        ErrorCode::EnterpriseAuthRequired,
        match kind {
            ProviderKind::Oidc => {
                "OIDC sign-in is not enabled on this server; see capabilities.auth"
            }
            ProviderKind::Ldap => {
                "directory sign-in is not enabled on this server; see capabilities.auth"
            }
        },
    )
}

/// A short plain-text page for the browser.
fn page(status: StatusCode, text: &'static str) -> Response {
    let mut resp = (status, text).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => {
            let mut resp = StatusCode::FOUND.into_response();
            resp.headers_mut().insert(header::LOCATION, v);
            resp
        }
        Err(_) => page(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in failed."),
    }
}

fn random_b64<const N: usize>() -> String {
    URL_SAFE_NO_PAD.encode(crypto::random_bytes::<N>())
}

fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(crypto::sha256(verifier.as_bytes()))
}

fn printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `GET /v1/auth/oidc/start` → `302` to the IdP.
pub async fn oidc_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    query: Result<Query<OidcStartQuery>, QueryRejection>,
) -> Response {
    let Some(oidc) = state.enterprise.as_ref().and_then(|e| e.oidc()) else {
        return page(
            StatusCode::NOT_FOUND,
            "SSO sign-in is not enabled on this server.",
        );
    };
    if let Err(e) = state.limits.check_auth_ip(ip) {
        return e.into_response();
    }
    let Ok(Query(q)) = query else {
        return page(
            StatusCode::BAD_REQUEST,
            "Invalid sign-in request. Update the ConsoleCrypt app and try again.",
        );
    };
    let hint_ok = q.login_hint.as_deref().is_none_or(|h| {
        h.len() <= limits::MAX_ENTERPRISE_LOGIN_LEN && !h.chars().any(char::is_control)
    });
    if !is_allowed_app_redirect_uri(&q.redirect_uri)
        || !is_valid_code_challenge(&q.code_challenge)
        || q.code_challenge_method
            .as_deref()
            .is_some_and(|m| m != CODE_CHALLENGE_METHOD_S256)
        || !printable(&q.state, limits::MAX_OIDC_STATE_LEN)
        || !hint_ok
        || q.device_id.as_uuid().is_nil()
    {
        metrics::counter!("cc_enterprise_logins_total", "method" => "oidc", "result" => "bad_start")
            .increment(1);
        return page(
            StatusCode::BAD_REQUEST,
            "Invalid sign-in request. Update the ConsoleCrypt app and try again.",
        );
    }
    let server_state = random_b64::<32>();
    let nonce = random_b64::<32>();
    let verifier = random_b64::<32>();
    let inserted = sqlx::query(
        "INSERT INTO oidc_flows
             (state_hash, nonce, pkce_verifier, app_redirect_uri, app_state, app_code_challenge,
              device_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
    )
    .bind(&crypto::sha256(server_state.as_bytes())[..])
    .bind(&nonce)
    .bind(&verifier)
    .bind(&q.redirect_uri)
    .bind(&q.state)
    .bind(&q.code_challenge)
    .bind(Uuid::from(q.device_id))
    .bind(limits::OIDC_FLOW_TTL_SECONDS as f64)
    .execute(&state.db)
    .await;
    if let Err(e) = inserted {
        return AppError::from(e).into_response();
    }
    redirect(&oidc.authorization_url(
        &server_state,
        &nonce,
        &s256(&verifier),
        q.login_hint.as_deref(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(sqlx::FromRow)]
struct FlowRow {
    nonce: String,
    pkce_verifier: String,
    app_redirect_uri: String,
    app_state: String,
    app_code_challenge: String,
    device_id: Uuid,
    live: bool,
}

/// Where the browser goes back to the app.
struct AppReturn {
    redirect_uri: String,
    state: String,
}

impl AppReturn {
    fn url(&self, pairs: &[(&str, &str)]) -> Response {
        let Ok(mut url) = reqwest::Url::parse(&self.redirect_uri) else {
            return page(StatusCode::INTERNAL_SERVER_ERROR, "Sign-in failed.");
        };
        {
            let mut q = url.query_pairs_mut();
            for (k, v) in pairs {
                q.append_pair(k, v);
            }
            q.append_pair(callback_params::STATE, &self.state);
        }
        redirect(url.as_str())
    }

    fn error(&self, err: &AppError) -> Response {
        let code = crate::util::enum_str(&err.code());
        let description = match err {
            AppError::Api { message, .. } => message.to_string(),
            _ => "sign-in failed".to_owned(),
        };
        self.url(&[
            (callback_params::ERROR, &code),
            (callback_params::ERROR_DESCRIPTION, &description),
        ])
    }
}

/// `GET /v1/auth/oidc/callback` (from the IdP) → `302` to the app.
pub async fn oidc_callback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    const EXPIRED: &str =
        "This sign-in has expired or was already used. Return to ConsoleCrypt and try again.";
    let Some(ent) = state.enterprise.clone() else {
        return page(
            StatusCode::NOT_FOUND,
            "SSO sign-in is not enabled on this server.",
        );
    };
    let Some(oidc) = ent.oidc() else {
        return page(
            StatusCode::NOT_FOUND,
            "SSO sign-in is not enabled on this server.",
        );
    };
    if let Err(e) = state.limits.check_auth_ip(ip) {
        return e.into_response();
    }
    let Ok(Query(q)) = query else {
        return page(StatusCode::BAD_REQUEST, EXPIRED);
    };
    let Some(server_state) = q.state.filter(|s| s.len() <= 256) else {
        return page(StatusCode::BAD_REQUEST, EXPIRED);
    };
    // Single use: the flow is deleted whatever happens next.
    let flow: Option<FlowRow> = match sqlx::query_as(
        "DELETE FROM oidc_flows WHERE state_hash = $1
         RETURNING nonce, pkce_verifier, app_redirect_uri, app_state, app_code_challenge,
                   device_id, expires_at > now() AS live",
    )
    .bind(&crypto::sha256(server_state.as_bytes())[..])
    .fetch_optional(&state.db)
    .await
    {
        Ok(f) => f,
        Err(e) => return AppError::from(e).into_response(),
    };
    let Some(flow) = flow.filter(|f| f.live) else {
        let err =
            AppError::invalid_credentials().with_details(serde_json::json!({ "reason": "state" }));
        audit_refusal(&state, None, ip, "oidc", &err).await;
        return page(StatusCode::BAD_REQUEST, EXPIRED);
    };
    let back = AppReturn {
        redirect_uri: flow.app_redirect_uri.clone(),
        state: flow.app_state.clone(),
    };
    match finish_callback(&state, &ent, oidc, ip, q.code, q.error, &flow).await {
        Ok(login_code) => back.url(&[(callback_params::LOGIN_CODE, &login_code)]),
        Err(err) => back.error(&err),
    }
}

async fn finish_callback(
    state: &AppState,
    ent: &super::Enterprise,
    oidc: &super::oidc::OidcProvider,
    ip: Option<IpAddr>,
    code: Option<String>,
    idp_error: Option<String>,
    flow: &FlowRow,
) -> AppResult<String> {
    if let Some(e) = idp_error {
        // The IdP's own description is not reflected (no injection).
        let err = if e == "access_denied" {
            AppError::forbidden("sign-in was cancelled or denied at the identity provider")
        } else {
            AppError::new(
                ErrorCode::IdpUnavailable,
                "the identity provider reported an error",
            )
        };
        audit_refusal(state, None, ip, "oidc", &err).await;
        return Err(err);
    }
    let Some(code) = code.filter(|c| !c.is_empty() && c.len() <= 4096) else {
        return Err(AppError::bad_request("missing authorization code"));
    };
    let tokens = match oidc.exchange_code(&code, &flow.pkce_verifier).await {
        Ok(t) => t,
        Err(UpstreamError::InvalidGrant) => {
            let err = AppError::invalid_credentials()
                .with_details(serde_json::json!({ "reason": "invalid_grant" }));
            audit_refusal(state, None, ip, "oidc", &err).await;
            return Err(err);
        }
        Err(UpstreamError::Unavailable(why)) => {
            tracing::warn!(why, "OIDC token endpoint failed");
            return Err(AppError::new(
                ErrorCode::IdpUnavailable,
                "the identity provider is unreachable; try again later",
            ));
        }
    };
    let Some(id_token) = tokens.id_token.as_deref() else {
        return Err(refuse(state, None, ip, "oidc", Refusal::Invalid("malformed")).await);
    };
    let claims = match oidc.validate_id_token(id_token, Some(&flow.nonce)).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(reason = e.reason(), "ID token rejected");
            return Err(refuse(state, None, ip, "oidc", Refusal::Invalid(e.reason())).await);
        }
    };
    let ident = match oidc.identity_from_claims(&state.config.auth, &claims) {
        Ok(i) => i,
        Err(r) => return Err(refuse(state, None, ip, "oidc", r).await),
    };
    let sealed = match (&tokens.refresh_token, &ent.token_box) {
        (Some(rt), Some(tb)) => Some(tb.seal(
            &token_context(ProviderKind::Oidc, &ident.issuer, &ident.subject),
            rt.expose_secret(),
        )),
        _ => {
            tracing::debug!("IdP issued no refresh token; re-checks need offline access");
            None
        }
    };
    let account = accounts::resolve(state, &ident, ip, sealed.as_deref()).await?;
    let login_code = crypto::issue_token(TokenKind::LoginCode);
    sqlx::query(
        "INSERT INTO oidc_login_codes (code_hash, user_id, code_challenge, device_id, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(&login_code.hash[..])
    .bind(Uuid::from(account.user_id))
    .bind(&flow.app_code_challenge)
    .bind(flow.device_id)
    .bind(limits::OIDC_LOGIN_CODE_TTL_SECONDS as f64)
    .execute(&state.db)
    .await?;
    Ok(login_code.token.expose_secret().to_owned())
}

#[derive(sqlx::FromRow)]
struct CodeRow {
    user_id: Uuid,
    code_challenge: String,
    device_id: Uuid,
}

/// `POST /v1/auth/oidc/exchange` → `AuthResponse`.
pub async fn oidc_exchange(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<OidcExchangeRequest>,
) -> AppResult<Json<AuthResponse>> {
    if state.enterprise.as_ref().and_then(|e| e.oidc()).is_none() {
        return Err(not_enabled(ProviderKind::Oidc));
    }
    state.limits.check_auth_ip(ip)?;
    devices::validate_registration(&req.device)?;
    let invalid = |reason: &'static str| {
        AppError::invalid_credentials().with_details(serde_json::json!({ "reason": reason }))
    };
    let Some(hash) =
        crypto::presented_token_hash(TokenKind::LoginCode, req.login_code.expose_secret())
    else {
        return Err(invalid("login_code"));
    };
    // Consumed by the first attempt, right or wrong: a stolen code cannot be
    // tried against several verifiers.
    let row: Option<CodeRow> = sqlx::query_as(
        "UPDATE oidc_login_codes SET used_at = now()
          WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
          RETURNING user_id, code_challenge, device_id",
    )
    .bind(&hash[..])
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else {
        let err = invalid("login_code");
        audit_refusal(&state, None, ip, "oidc", &err).await;
        return Err(err);
    };
    let user_id = UserId::from(row.user_id);
    let verifier = req.code_verifier.expose_secret();
    if !is_valid_code_verifier(verifier)
        || !crypto::ct_eq(s256(verifier).as_bytes(), row.code_challenge.as_bytes())
    {
        let err = invalid("code_verifier");
        audit_refusal(&state, Some(user_id), ip, "oidc", &err).await;
        return Err(err);
    }
    if req.device.device_id != DeviceId::from(row.device_id) {
        let err = invalid("device_id");
        audit_refusal(&state, Some(user_id), ip, "oidc", &err).await;
        return Err(err);
    }
    accounts::complete_login(
        &state,
        ip,
        user_id,
        &req.device,
        req.device_proof.as_ref(),
        "oidc",
    )
    .await
    .map(Json)
}

/// `POST /v1/auth/ldap/login` → `AuthResponse`.
pub async fn ldap_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<LdapLoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let Some(ent) = state.enterprise.clone() else {
        return Err(not_enabled(ProviderKind::Ldap));
    };
    let Some(ldap) = ent.ldap() else {
        return Err(not_enabled(ProviderKind::Ldap));
    };
    let cfg = &ldap.cfg;
    state.limits.check_auth_ip(ip)?;
    devices::validate_registration(&req.device)?;
    let login = req.login.trim();
    let password = &req.password;
    // Malformed input never reaches the directory and looks like any other
    // failed sign-in.
    if login.is_empty()
        || login.len() > limits::MAX_ENTERPRISE_LOGIN_LEN
        || login.chars().any(char::is_control)
        || password.expose_secret().is_empty()
        || password.expose_secret().len() > limits::MAX_ACCOUNT_PASSWORD_LEN
    {
        return Err(AppError::invalid_credentials());
    }
    let normalized = lockout::normalize_login(login);
    state
        .limits
        .login_email
        .check(&crate::util::email_key(&normalized))?;
    let window = cfg.failure_window;
    let ip_key = ip.map(lockout::ip_key);
    if let Some(k) = &ip_key {
        lockout::check(&state.db, Scope::Ip, k, cfg.max_failures_per_ip, window).await?;
    }
    let login_key = lockout::key(Scope::Login, &normalized);
    lockout::reserve(
        &state.db,
        Scope::Login,
        &login_key,
        cfg.max_failures,
        window,
    )
    .await?;

    let unavailable = |why: &'static str| {
        tracing::warn!(why, "LDAP directory unavailable during sign-in");
        AppError::new(
            ErrorCode::IdpUnavailable,
            "the directory is unreachable; try again later",
        )
    };
    let failed = |user: Option<UserId>| {
        let state = state.clone();
        async move {
            if let Some(k) = &ip_key {
                if let Err(e) = lockout::record_failure(&state.db, Scope::Ip, k, window).await {
                    return e;
                }
            }
            metrics::counter!("cc_auth_failures_total", "reason" => "ldap_invalid_credentials")
                .increment(1);
            let err = AppError::invalid_credentials();
            audit_refusal(&state, user, ip, "ldap", &err).await;
            err
        }
    };

    let user = match ldap.find_user(login).await {
        Ok(u) => u,
        Err(super::ldap::Unavailable(why)) => return Err(unavailable(why)),
    };
    let Some(user) = user else {
        return Err(failed(None).await);
    };
    let user_key = lockout::key(Scope::User, &user.subject);
    lockout::reserve(&state.db, Scope::User, &user_key, cfg.max_failures, window).await?;
    match ldap.verify_password(&user, password).await {
        Ok(true) => {}
        Ok(false) => return Err(failed(None).await),
        Err(super::ldap::Unavailable(why)) => return Err(unavailable(why)),
    }
    lockout::clear(&state.db, Scope::Login, &login_key).await?;
    lockout::clear(&state.db, Scope::User, &user_key).await?;
    if user.disabled {
        return Err(refuse(&state, None, ip, "ldap", Refusal::AccountDisabled).await);
    }
    if !user.in_group {
        return Err(refuse(&state, None, ip, "ldap", Refusal::GroupRequired).await);
    }
    let ident = VerifiedIdentity {
        provider: ProviderKind::Ldap,
        issuer: ldap.issuer.clone(),
        subject: user.subject.clone(),
        email: user.email.clone(),
        email_verified: true,
    };
    let account = accounts::resolve(&state, &ident, ip, None).await?;
    accounts::complete_login(
        &state,
        ip,
        account.user_id,
        &req.device,
        req.device_proof.as_ref(),
        "ldap",
    )
    .await
    .map(Json)
}
