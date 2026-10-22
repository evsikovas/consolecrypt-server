// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! OIDC relying party (ТР-4, ТР-7): the server is a confidential client of
//! the IdP (authorization code + PKCE S256 + nonce + state).
//!
//! Startup ([`OidcProvider::discover`]) fetches the discovery document,
//! requires its `issuer` to equal `CC_OIDC_ISSUER` exactly and loads the JWKS;
//! any failure stops the server with a clear message. Tokens from the IdP are
//! never logged.

use super::jwt::{self, Expectations, JwkSet, JwtError};
use super::secrets::read_secret_file;
use super::{claim_contains, claim_str, Refusal, VerifiedIdentity};
use crate::config::{check_idp_url, AuthConfig, OidcConfig, OidcPreset, TokenAuthMethod};
use cc_protocol::auth::SecretString;
use serde_json::{Map, Value};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Minimum spacing of JWKS refetches triggered by an unknown `kid`.
const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// `amr` values meaning multi-factor (RFC 8176 `mfa`; AD FS URI).
const MFA_AMR: &[&str] = &["mfa", "http://schemas.microsoft.com/claims/multipleauthn"];

#[derive(Debug, Clone)]
struct Metadata {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Outcome of a call to the IdP token endpoint.
#[derive(Debug)]
pub enum UpstreamError {
    /// The grant was rejected (`invalid_grant`): the user was disabled,
    /// deleted, or the IdP session was revoked.
    InvalidGrant,
    /// Network error, timeout, 5xx, unexpected response or client
    /// misconfiguration: not the user's fault.
    Unavailable(&'static str),
}

/// Tokens from the IdP. `Debug` is redacted.
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub refresh_token: Option<SecretString>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

pub struct OidcProvider {
    pub cfg: OidcConfig,
    client_secret: SecretString,
    http: reqwest::Client,
    metadata: Metadata,
    jwks: RwLock<JwkSet>,
    /// Last refetch triggered by an unknown `kid` (not the startup fetch).
    last_jwks_refetch: Mutex<Option<Instant>>,
    /// `CC_PUBLIC_URL` + `/v1/auth/oidc/callback`, registered at the IdP.
    pub callback_url: String,
}

impl fmt::Debug for OidcProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProvider")
            .field("issuer", &self.cfg.issuer)
            .field("client_id", &self.cfg.client_id)
            .field("callback_url", &self.callback_url)
            .finish_non_exhaustive()
    }
}

fn http_client(cfg: &OidcConfig) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!("consolecrypt-server/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = &cfg.ca_file {
        let pem = super::secrets::read_bytes("CC_OIDC_CA_FILE", path)?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| {
            anyhow::anyhow!(
                "CC_OIDC_CA_FILE ({}): not a PEM certificate",
                path.display()
            )
        })?;
        if certs.is_empty() {
            anyhow::bail!("CC_OIDC_CA_FILE ({}): no certificate found", path.display());
        }
        builder = builder.tls_certs_merge(certs);
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("cannot initialise the HTTPS client for the IdP"))
}

async fn get_json(http: &reqwest::Client, url: &str, what: &str) -> anyhow::Result<Vec<u8>> {
    let resp = http
        .get(url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{what}: cannot reach {url} ({})", reqwest_kind(&e)))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("{what}: {url} answered HTTP {}", status.as_u16());
    }
    let body = read_limited(resp)
        .await
        .map_err(|_| anyhow::anyhow!("{what}: cannot read the response from {url}"))?;
    Ok(body)
}

async fn read_limited(resp: reqwest::Response) -> Result<Vec<u8>, ()> {
    if resp
        .content_length()
        .is_some_and(|l| l > MAX_RESPONSE_BYTES as u64)
    {
        return Err(());
    }
    let bytes = resp.bytes().await.map_err(|_| ())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(());
    }
    Ok(bytes.to_vec())
}

fn reqwest_kind(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection failed (DNS, TLS or refused)"
    } else {
        "request failed"
    }
}

impl OidcProvider {
    /// Read secrets, fetch discovery + JWKS and validate them (§3.5).
    pub async fn discover(cfg: &OidcConfig, public_url: &str) -> anyhow::Result<Self> {
        let client_secret =
            read_secret_file("CC_OIDC_CLIENT_SECRET_FILE", &cfg.client_secret_file)?;
        let http = http_client(cfg)?;
        let metadata = fetch_metadata(&http, cfg).await?;
        let jwks_body = get_json(&http, &metadata.jwks_uri, "OIDC JWKS").await?;
        let jwks = JwkSet::parse(&jwks_body)
            .map_err(|_| anyhow::anyhow!("OIDC JWKS at {}: not a JWK set", metadata.jwks_uri))?;
        if jwks.is_empty() {
            anyhow::bail!(
                "OIDC JWKS at {}: no RS256/PS256/ES256 signing key (other algorithms are not accepted)",
                metadata.jwks_uri
            );
        }
        Ok(Self {
            cfg: cfg.clone(),
            client_secret,
            http,
            metadata,
            jwks: RwLock::new(jwks),
            last_jwks_refetch: Mutex::new(None),
            callback_url: format!(
                "{}{}",
                public_url.trim_end_matches('/'),
                cc_protocol::paths::AUTH_OIDC_CALLBACK
            ),
        })
    }

    /// Re-run the discovery/JWKS checks (admin `auth test`, status).
    pub async fn check(&self) -> anyhow::Result<String> {
        let metadata = fetch_metadata(&self.http, &self.cfg).await?;
        let body = get_json(&self.http, &metadata.jwks_uri, "OIDC JWKS").await?;
        let jwks = JwkSet::parse(&body)
            .map_err(|_| anyhow::anyhow!("OIDC JWKS at {}: not a JWK set", metadata.jwks_uri))?;
        if jwks.is_empty() {
            anyhow::bail!("OIDC JWKS at {}: no usable signing key", metadata.jwks_uri);
        }
        let n = jwks.len();
        *self.jwks.write().await = jwks;
        Ok(format!(
            "discovery ok (issuer {}), {n} signing key(s)",
            self.cfg.issuer
        ))
    }

    /// The IdP authorization request URL.
    pub fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
        login_hint: Option<&str>,
    ) -> String {
        let mut url = reqwest::Url::parse(&self.metadata.authorization_endpoint)
            .expect("validated at startup");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", &self.callback_url)
                .append_pair("scope", &self.cfg.scopes.join(" "))
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(h) = login_hint {
                q.append_pair("login_hint", h);
            }
            for (k, v) in &self.cfg.extra_auth_params {
                q.append_pair(k, v);
            }
        }
        url.into()
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenResponse, UpstreamError> {
        let mut fields: Vec<(&str, &str)> = form.to_vec();
        let mut req = self.http.post(&self.metadata.token_endpoint);
        match self.cfg.token_auth_method {
            TokenAuthMethod::Basic => {
                // RFC 6749 2.3.1: form-urlencode id and secret first.
                let id = form_encode(&self.cfg.client_id);
                let secret = form_encode(self.client_secret.expose_secret());
                req = req.basic_auth(id, Some(secret));
            }
            TokenAuthMethod::Post => {
                fields.push(("client_id", &self.cfg.client_id));
                fields.push(("client_secret", self.client_secret.expose_secret()));
            }
        }
        let resp = req
            .header("accept", "application/json")
            .form(&fields)
            .send()
            .await
            .map_err(|e| UpstreamError::Unavailable(reqwest_kind(&e)))?;
        let status = resp.status();
        let body = read_limited(resp)
            .await
            .map_err(|_| UpstreamError::Unavailable("unreadable token response"))?;
        let json: Map<String, Value> = serde_json::from_slice(&body)
            .map_err(|_| UpstreamError::Unavailable("token response is not JSON"))?;
        if !status.is_success() {
            return Err(match json.get("error").and_then(Value::as_str) {
                Some("invalid_grant") => UpstreamError::InvalidGrant,
                Some("invalid_client" | "unauthorized_client") => {
                    UpstreamError::Unavailable("IdP rejected the client credentials")
                }
                _ if status.is_server_error() => UpstreamError::Unavailable("IdP server error"),
                _ => UpstreamError::Unavailable("IdP rejected the token request"),
            });
        }
        Ok(TokenResponse {
            id_token: json
                .get("id_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
            refresh_token: json
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty() && t.len() <= 8192)
                .map(SecretString::new),
        })
    }

    /// Redeem an authorization code (with the server-side PKCE verifier).
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<TokenResponse, UpstreamError> {
        self.token_request(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.callback_url),
            ("code_verifier", pkce_verifier),
        ])
        .await
    }

    /// Refresh grant (re-check, ТР-6).
    pub async fn refresh(
        &self,
        refresh_token: &SecretString,
    ) -> Result<TokenResponse, UpstreamError> {
        self.token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_secret()),
        ])
        .await
    }

    /// Verify an ID token; an unknown `kid` triggers one JWKS refetch, at
    /// most every [`JWKS_REFETCH_INTERVAL`] (key rotation at the IdP).
    pub async fn validate_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<Map<String, Value>, JwtError> {
        let expect = Expectations {
            issuer: &self.cfg.issuer,
            client_id: &self.cfg.client_id,
            nonce,
            now: chrono::Utc::now().timestamp(),
        };
        let first = jwt::verify(token, &*self.jwks.read().await, &expect);
        match first {
            Err(JwtError::UnknownKey) if self.may_refetch_jwks() => {
                metrics::counter!("cc_oidc_jwks_refetch_total").increment(1);
                match get_json(&self.http, &self.metadata.jwks_uri, "OIDC JWKS").await {
                    Ok(body) => {
                        if let Ok(set) = JwkSet::parse(&body) {
                            if !set.is_empty() {
                                *self.jwks.write().await = set;
                            }
                        }
                    }
                    Err(_) => tracing::warn!("OIDC JWKS refetch failed"),
                }
                jwt::verify(token, &*self.jwks.read().await, &expect)
            }
            other => other,
        }
    }

    fn may_refetch_jwks(&self) -> bool {
        let mut last = self.last_jwks_refetch.lock().expect("lock");
        if last.is_some_and(|t| t.elapsed() < JWKS_REFETCH_INTERVAL) {
            false
        } else {
            *last = Some(Instant::now());
            true
        }
    }

    /// Identity from verified ID token claims, with the sign-in policy
    /// (required claim, MFA, Google hosted domain) applied.
    pub fn identity_from_claims(
        &self,
        auth: &AuthConfig,
        claims: &Map<String, Value>,
    ) -> Result<VerifiedIdentity, Refusal> {
        let subject = claim_str(claims, "sub")
            .ok_or(Refusal::Invalid("sub"))?
            .to_owned();
        self.check_policy(auth, claims)?;
        let email = claim_str(claims, &self.cfg.email_claim)
            .map(|e| e.trim().to_owned())
            .filter(|e| e.contains('@'));
        let email_verified = match claims.get("email_verified") {
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::String(s)) => Some(s == "true"),
            _ => None,
        };
        Ok(VerifiedIdentity {
            provider: crate::config::ProviderKind::Oidc,
            issuer: self.cfg.issuer.clone(),
            subject,
            email,
            // Only an explicit `false` counts against the email; Entra and
            // AD FS do not send the claim (the domain list is the guard).
            email_verified: email_verified != Some(false),
        })
    }

    /// Required claim / MFA / hosted domain. Also used by the re-check.
    pub fn check_policy(
        &self,
        auth: &AuthConfig,
        claims: &Map<String, Value>,
    ) -> Result<(), Refusal> {
        if let Some((name, value)) = &self.cfg.required_claim {
            if !claim_contains(claims, name, value) {
                if name == "groups"
                    && claims
                        .get("_claim_names")
                        .and_then(|v| v.get("groups"))
                        .is_some()
                {
                    tracing::warn!(
                        "ID token has a groups overage (too many groups): use Entra app roles \
                         (CC_OIDC_REQUIRED_CLAIM=roles=…) or assign groups to the application"
                    );
                }
                return Err(Refusal::GroupRequired);
            }
        }
        if self.cfg.require_mfa {
            let amr_mfa = claims
                .get("amr")
                .and_then(Value::as_array)
                .is_some_and(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .any(|v| MFA_AMR.contains(&v))
                });
            let acr_mfa = claim_str(claims, "acr")
                .is_some_and(|acr| self.cfg.mfa_acr_values.iter().any(|v| v == acr));
            if !amr_mfa && !acr_mfa {
                return Err(Refusal::MfaRequired);
            }
        }
        if self.cfg.preset == OidcPreset::Google {
            // `hd` is set only for Workspace accounts; a consumer account with
            // a corporate-looking email has none.
            let hd = claim_str(claims, "hd").map(str::to_ascii_lowercase);
            if !hd.is_some_and(|d| auth.allowed_domains.contains(&d)) {
                return Err(Refusal::DomainNotAllowed);
            }
        }
        Ok(())
    }
}

/// `application/x-www-form-urlencoded` encoding of one value.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn fetch_metadata(http: &reqwest::Client, cfg: &OidcConfig) -> anyhow::Result<Metadata> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let body = get_json(http, &url, "OIDC discovery").await?;
    let doc: Map<String, Value> = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("OIDC discovery at {url}: not a JSON object"))?;
    let s = |k: &str| doc.get(k).and_then(Value::as_str).map(str::to_owned);
    let issuer = s("issuer").unwrap_or_default();
    if issuer != cfg.issuer {
        anyhow::bail!(
            "OIDC discovery: issuer mismatch — CC_OIDC_ISSUER is {:?} but the IdP reports {:?} \
             (they must be identical, including the trailing slash)",
            cfg.issuer,
            issuer
        );
    }
    let field =
        |k: &str| s(k).ok_or_else(|| anyhow::anyhow!("OIDC discovery at {url}: {k} missing"));
    let metadata = Metadata {
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
        jwks_uri: field("jwks_uri")?,
    };
    for (k, v) in [
        ("authorization_endpoint", &metadata.authorization_endpoint),
        ("token_endpoint", &metadata.token_endpoint),
        ("jwks_uri", &metadata.jwks_uri),
    ] {
        check_idp_url(&format!("OIDC discovery {k}"), v).map_err(|e| anyhow::anyhow!("{e}"))?;
        reqwest::Url::parse(v).map_err(|_| anyhow::anyhow!("OIDC discovery {k}: invalid URL"))?;
    }
    if let Some(algs) = doc
        .get("id_token_signing_alg_values_supported")
        .and_then(Value::as_array)
    {
        let ok = algs
            .iter()
            .filter_map(Value::as_str)
            .any(|a| matches!(a, "RS256" | "PS256" | "ES256"));
        if !ok {
            anyhow::bail!(
                "OIDC discovery: the IdP signs ID tokens with none of RS256, PS256, ES256"
            );
        }
    }
    if let Some(methods) = doc
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
    {
        if !methods.iter().any(|m| m.as_str() == Some("S256")) {
            anyhow::bail!("OIDC discovery: the IdP does not support PKCE S256");
        }
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding() {
        assert_eq!(form_encode("a b+c/d:é"), "a+b%2Bc%2Fd%3A%C3%A9");
        assert_eq!(form_encode("Abc-._*"), "Abc-._*");
    }

    #[test]
    fn token_response_debug_is_redacted() {
        let t = TokenResponse {
            id_token: Some("eyJ.secret".into()),
            refresh_token: Some("rt-secret".into()),
        };
        let d = format!("{t:?}");
        assert!(!d.contains("secret"), "{d}");
    }
}
