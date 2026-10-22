//! Enterprise sign-in (protocol 1.9): the account is authenticated by the
//! organisation's identity source instead of an account password.
//!
//! Active only while `/v1/meta` advertises
//! `capabilities.auth.mode = "enterprise"` (see
//! [`crate::meta::AuthCapability`]). In that mode `register`, password
//! `login`, password reset/change and email verification answer
//! `403 enterprise_auth_required`.
//!
//! Like the account password, nothing here ever decrypts a vault: after an
//! IdP/LDAP sign-in the device is an ordinary new device (device protection,
//! vault passphrase / Recovery Key / approval).
//!
//! ## OIDC (`provider = "oidc"`)
//!
//! The server is a confidential client of the IdP; the app is a public client
//! of the server; PKCE (S256) protects both legs.
//!
//! 1. The app creates a `code_verifier` (RFC 7636: 43–128 characters of
//!    `[A-Za-z0-9-._~]`), `code_challenge = BASE64URL-NOPAD(SHA-256(verifier))`
//!    and a random `state`, starts a redirect listener and opens the system
//!    browser at [`OidcStartQuery::to_url`] (`GET /v1/auth/oidc/start`).
//! 2. The server redirects to the IdP; the IdP returns to
//!    `GET /v1/auth/oidc/callback` (server-side, not for apps).
//! 3. The server redirects the browser to the app's `redirect_uri` with
//!    either `login_code` + `state`, or `error` + `error_description` +
//!    `state` (see [`OidcAppCallback`]). `error` is an [`crate::ErrorCode`]
//!    in snake_case (`domain_not_allowed`, `group_required`, `mfa_required`,
//!    `identity_conflict`, `idp_unavailable`, `account_disabled`,
//!    `invalid_credentials`, `bad_request`, …). The app MUST compare `state`
//!    with the one it generated.
//! 4. The app redeems the code: `POST /v1/auth/oidc/exchange`
//!    [`OidcExchangeRequest`] → [`crate::auth::AuthResponse`]. The
//!    `login_code` lives [`crate::limits::OIDC_LOGIN_CODE_TTL_SECONDS`], is
//!    single use and bound to the `code_challenge` and `device_id` given at
//!    step 1.
//!
//! Allowed app redirect URIs ([`is_allowed_app_redirect_uri`]):
//! `http://127.0.0.1:{port}/auth/callback`, `http://[::1]:{port}/auth/callback`
//! (desktop, RFC 8252 loopback) and `consolecrypt://auth/callback` (mobile).
//!
//! ## LDAP / Active Directory (`provider = "ldap"`)
//!
//! `POST /v1/auth/ldap/login` [`LdapLoginRequest`] → `AuthResponse`. An
//! unknown login and a wrong password both answer `401 invalid_credentials`.
//!
//! ## Refresh
//!
//! `POST /v1/auth/refresh` may answer `403 account_disabled` when the
//! periodic re-check finds the user disabled, deleted or outside the
//! required group in the IdP/directory; the whole session family is revoked
//! and the app should lock the synced profile ("access disabled by the
//! administrator").

use crate::auth::SecretString;
use crate::devices::{DeviceProof, DeviceRegistration};
use crate::ids::DeviceId;
use serde::{Deserialize, Serialize};

/// The only `code_challenge_method` accepted.
pub const CODE_CHALLENGE_METHOD_S256: &str = "S256";

/// Path of the app's redirect URI (loopback and custom scheme).
pub const APP_REDIRECT_PATH: &str = "/auth/callback";
/// Redirect URI used by the mobile apps (Android, iOS).
pub const APP_REDIRECT_URI_MOBILE: &str = "consolecrypt://auth/callback";

/// Query parameter names of the redirect back to the app (step 3).
pub mod callback_params {
    pub const LOGIN_CODE: &str = "login_code";
    pub const STATE: &str = "state";
    pub const ERROR: &str = "error";
    pub const ERROR_DESCRIPTION: &str = "error_description";
}

/// Query of `GET /v1/auth/oidc/start` (opened in the system browser).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcStartQuery {
    /// Where the server sends the browser back; see
    /// [`is_allowed_app_redirect_uri`].
    pub redirect_uri: String,
    /// `BASE64URL-NOPAD(SHA-256(code_verifier))`, exactly 43 characters.
    pub code_challenge: String,
    /// Only `"S256"`; may be omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    /// Opaque app state echoed back unchanged (1–512 URL-safe characters).
    pub state: String,
    /// The device that will redeem the `login_code`.
    pub device_id: DeviceId,
    /// Optional email/username to prefill at the IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
}

impl OidcStartQuery {
    /// Full URL to open in the browser. `server_base` is the server's base
    /// URL without trailing slash (e.g. `https://sync.example.com`).
    pub fn to_url(&self, server_base: &str) -> String {
        let mut url = format!(
            "{}{}?redirect_uri={}&code_challenge={}&state={}&device_id={}",
            server_base.trim_end_matches('/'),
            crate::paths::AUTH_OIDC_START,
            percent_encode(&self.redirect_uri),
            percent_encode(&self.code_challenge),
            percent_encode(&self.state),
            percent_encode(&self.device_id.to_string()),
        );
        if let Some(m) = &self.code_challenge_method {
            url.push_str("&code_challenge_method=");
            url.push_str(&percent_encode(m));
        }
        if let Some(h) = &self.login_hint {
            url.push_str("&login_hint=");
            url.push_str(&percent_encode(h));
        }
        url
    }
}

/// Query parameters the app receives on its `redirect_uri` (step 3).
/// Exactly one of `login_code` / `error` is present.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcAppCallback {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_code: Option<SecretString>,
    #[serde(default)]
    pub state: String,
    /// An [`crate::ErrorCode`] in snake_case. Kept as a string so a code
    /// added later still reaches the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl std::fmt::Debug for OidcAppCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAppCallback")
            .field(
                "login_code",
                &self.login_code.as_ref().map(|_| "<redacted>"),
            )
            .field("state", &self.state)
            .field("error", &self.error)
            .field("error_description", &self.error_description)
            .finish()
    }
}

/// `POST /v1/auth/oidc/exchange` → [`crate::auth::AuthResponse`]
///
/// Errors: `401 invalid_credentials` (unknown, expired or already used
/// `login_code`, wrong `code_verifier`, other `device_id`), `422
/// invalid_proof` (as for password login), `403 enterprise_auth_required`
/// (server not in OIDC mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcExchangeRequest {
    pub login_code: SecretString,
    pub code_verifier: SecretString,
    /// `device.device_id` must equal the `device_id` given to `start`.
    pub device: DeviceRegistration,
    /// Required when the device is already registered (as for password
    /// login, protocol 1.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<DeviceProof>,
}

/// `POST /v1/auth/ldap/login` → [`crate::auth::AuthResponse`]
///
/// Errors: `401 invalid_credentials` (unknown login or wrong password,
/// indistinguishable), `403 account_disabled`, `403 group_required`, `403
/// domain_not_allowed`, `409 identity_conflict`, `503 idp_unavailable`,
/// `429 rate_limited`, `403 enterprise_auth_required` (server not in LDAP
/// mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapLoginRequest {
    /// Email, UPN or `DOMAIN\user` / `sAMAccountName`, as the operator's
    /// filter accepts.
    pub login: String,
    /// Directory password. Sent over TLS, never stored or logged.
    pub password: SecretString,
    pub device: DeviceRegistration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<DeviceProof>,
}

/// Whether `uri` is one of the redirect URIs an app may use (exact match,
/// no query, fragment or user info):
///
/// * `http://127.0.0.1:{port}/auth/callback`
/// * `http://[::1]:{port}/auth/callback`
/// * `consolecrypt://auth/callback`
///
/// `{port}` is 1–65535 without leading zeros.
pub fn is_allowed_app_redirect_uri(uri: &str) -> bool {
    if uri == APP_REDIRECT_URI_MOBILE {
        return true;
    }
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let rest = if let Some(r) = rest.strip_prefix("127.0.0.1:") {
        r
    } else if let Some(r) = rest.strip_prefix("[::1]:") {
        r
    } else {
        return false;
    };
    let Some((port, path)) = rest.split_once('/') else {
        return false;
    };
    if format!("/{path}") != APP_REDIRECT_PATH {
        return false;
    }
    if port.is_empty() || port.len() > 5 || port.starts_with('0') {
        return false;
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    matches!(port.parse::<u32>(), Ok(1..=65535))
}

/// Whether `s` is a syntactically valid RFC 7636 `code_verifier`.
pub fn is_valid_code_verifier(s: &str) -> bool {
    (43..=128).contains(&s.len()) && s.bytes().all(is_unreserved)
}

/// Whether `s` looks like an S256 `code_challenge` (43 base64url chars).
pub fn is_valid_code_challenge(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// RFC 3986 percent-encoding of everything except unreserved characters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_allow_list() {
        for ok in [
            "http://127.0.0.1:1/auth/callback",
            "http://127.0.0.1:49152/auth/callback",
            "http://127.0.0.1:65535/auth/callback",
            "http://[::1]:8080/auth/callback",
            "consolecrypt://auth/callback",
        ] {
            assert!(is_allowed_app_redirect_uri(ok), "{ok}");
        }
        for bad in [
            "http://127.0.0.1/auth/callback",
            "http://127.0.0.1:0/auth/callback",
            "http://127.0.0.1:065/auth/callback",
            "http://127.0.0.1:65536/auth/callback",
            "http://127.0.0.1:80/auth/callback/",
            "http://127.0.0.1:80/auth/callback?x=1",
            "http://127.0.0.1:80/auth/callback#x",
            "http://127.0.0.1:80/other",
            "http://localhost:80/auth/callback",
            "http://127.0.0.2:80/auth/callback",
            "http://evil@127.0.0.1:80/auth/callback",
            "https://127.0.0.1:80/auth/callback",
            "http://127.0.0.1:80@evil.com/auth/callback",
            "consolecrypt://auth/callback/",
            "consolecrypt://auth/callback?x",
            "consolecrypt://evil/auth/callback",
            "https://evil.example/auth/callback",
            "",
        ] {
            assert!(!is_allowed_app_redirect_uri(bad), "{bad}");
        }
    }

    #[test]
    fn pkce_syntax() {
        assert!(is_valid_code_verifier(&"a".repeat(43)));
        assert!(is_valid_code_verifier(&"A-._~".repeat(20)));
        assert!(!is_valid_code_verifier(&"a".repeat(42)));
        assert!(!is_valid_code_verifier(&"a".repeat(129)));
        assert!(!is_valid_code_verifier(&format!("{}+", "a".repeat(43))));
        assert!(is_valid_code_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!is_valid_code_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="
        ));
    }

    #[test]
    fn start_url_is_encoded() {
        let q = OidcStartQuery {
            redirect_uri: "http://127.0.0.1:5000/auth/callback".into(),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
            code_challenge_method: Some("S256".into()),
            state: "s t".into(),
            device_id: DeviceId::from(uuid::Uuid::nil()),
            login_hint: Some("a+b@acme.com".into()),
        };
        let url = q.to_url("https://sync.example.com/");
        assert_eq!(
            url,
            "https://sync.example.com/v1/auth/oidc/start\
             ?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fauth%2Fcallback\
             &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
             &state=s%20t&device_id=00000000-0000-0000-0000-000000000000\
             &code_challenge_method=S256&login_hint=a%2Bb%40acme.com"
        );
    }

    #[test]
    fn callback_debug_redacts_code() {
        let cb = OidcAppCallback {
            login_code: Some("ccl_secret".into()),
            state: "x".into(),
            ..Default::default()
        };
        assert!(!format!("{cb:?}").contains("ccl_secret"));
    }
}
