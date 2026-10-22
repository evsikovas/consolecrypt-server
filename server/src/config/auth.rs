// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Sign-in mode configuration (`CC_AUTH_*`, `CC_OIDC_*`, `CC_LDAP_*`,
//! protocol 1.8). Parsing and offline sanity checks only: secrets stay in
//! their files (read by `crate::enterprise` at startup) and the network
//! checks (discovery, JWKS, LDAP bind) run when the server starts.

use super::{parse_bool, parse_or, ConfigError};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthModeKind {
    /// Email + account password (default; behaviour of 0.1.x).
    Standard,
    /// Sign-in only through the configured IdP or directory.
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Oidc,
    Ldap,
}

impl ProviderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Oidc => "oidc",
            ProviderKind::Ldap => "ldap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcPreset {
    Generic,
    Entra,
    Adfs,
    Keycloak,
    Google,
    Okta,
}

impl OidcPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            OidcPreset::Generic => "generic",
            OidcPreset::Entra => "entra",
            OidcPreset::Adfs => "adfs",
            OidcPreset::Keycloak => "keycloak",
            OidcPreset::Google => "google",
            OidcPreset::Okta => "okta",
        }
    }
}

/// How the server authenticates to the IdP token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuthMethod {
    /// `client_secret_basic` (HTTP Basic, default).
    Basic,
    /// `client_secret_post` (form fields).
    Post,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub preset: OidcPreset,
    /// Exact issuer; must equal the discovery document's `issuer` and every
    /// ID token's `iss`.
    pub issuer: String,
    pub client_id: String,
    /// File holding the client secret (Kubernetes Secret / Docker secret).
    pub client_secret_file: PathBuf,
    pub scopes: Vec<String>,
    /// ID token claim used as the account email.
    pub email_claim: String,
    /// `name=value`: only identities whose claim `name` equals or contains
    /// `value` may sign in.
    pub required_claim: Option<(String, String)>,
    pub require_mfa: bool,
    /// `acr` values accepted as multi-factor (in addition to `amr`).
    pub mfa_acr_values: Vec<String>,
    /// 32-byte key (raw, hex or base64) sealing upstream refresh tokens.
    pub token_key_file: PathBuf,
    pub token_auth_method: TokenAuthMethod,
    /// Extra trusted root for the IdP (e.g. an internal AD FS CA).
    pub ca_file: Option<PathBuf>,
    /// Extra authorization request parameters added by the preset.
    pub extra_auth_params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// `ldaps://host:636` or `ldap://host:389` (then STARTTLS is mandatory).
    pub url: String,
    pub starttls: bool,
    pub ca_file: Option<PathBuf>,
    pub bind_dn: String,
    pub bind_password_file: PathBuf,
    pub base_dn: String,
    /// Search filter with a `{login}` placeholder (RFC 4515-escaped input).
    pub user_filter: String,
    pub email_attr: String,
    /// Stable identifier attribute (`objectGUID` for Active Directory).
    pub id_attr: String,
    /// Group DN the user must be a (possibly nested) member of.
    pub required_group: Option<String>,
    pub timeout: Duration,
    /// Failed binds per login within `failure_window` before further attempts
    /// for that login are refused without contacting the directory. Keep it
    /// below the domain's account lockout threshold.
    pub max_failures: u32,
    pub failure_window: Duration,
    /// Failed logins per client IP within `failure_window` (0 = no limit).
    pub max_failures_per_ip: u32,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthModeKind,
    /// Set iff `mode` is enterprise.
    pub provider: Option<ProviderKind>,
    /// Name on the app's sign-in button ("Sign in with …").
    pub display_name: Option<String>,
    /// Lower-case email domains allowed to sign in (empty = any).
    pub allowed_domains: Vec<String>,
    /// Create an account on the first sign-in of a new identity.
    pub auto_create: bool,
    /// Re-check the user at the IdP/directory at most this often.
    pub recheck_interval: Duration,
    /// How long sessions survive while the IdP/directory is unreachable.
    pub recheck_grace: Duration,
    pub oidc: Option<OidcConfig>,
    pub ldap: Option<LdapConfig>,
}

impl AuthConfig {
    pub fn is_enterprise(&self) -> bool {
        self.mode == AuthModeKind::Enterprise
    }

    /// The configured enterprise provider, if any.
    pub fn enterprise_provider(&self) -> Option<ProviderKind> {
        if self.is_enterprise() {
            self.provider
        } else {
            None
        }
    }

    pub fn standard() -> Self {
        Self {
            mode: AuthModeKind::Standard,
            provider: None,
            display_name: None,
            allowed_domains: Vec::new(),
            auto_create: true,
            recheck_interval: Duration::from_secs(15 * 60),
            recheck_grace: Duration::from_secs(24 * 3600),
            oidc: None,
            ldap: None,
        }
    }

    /// Whether `email`'s domain may sign in (always true without a list).
    pub fn domain_allowed(&self, email: &str) -> bool {
        if self.allowed_domains.is_empty() {
            return true;
        }
        email_domain(email).is_some_and(|d| self.allowed_domains.contains(&d))
    }
}

/// Lower-case domain of an email address.
pub fn email_domain(email: &str) -> Option<String> {
    let (_, domain) = email.trim().rsplit_once('@')?;
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

fn list(v: Option<String>, sep: impl Fn(char) -> bool) -> Vec<String> {
    v.map(|s| {
        s.split(sep)
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

fn err<T>(m: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(m.into()))
}

/// Whether `url` is http(s) on a loopback host (development IdPs only).
pub fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match host.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

/// Validate an IdP URL: https, or http on loopback (development).
pub fn check_idp_url(what: &str, url: &str) -> Result<(), ConfigError> {
    if url.starts_with("https://") && url.len() > "https://".len() {
        return Ok(());
    }
    if is_loopback_http(url) {
        return Ok(());
    }
    err(format!(
        "{what} must be an https:// URL (http:// only on 127.0.0.1/localhost for development)"
    ))
}

impl AuthConfig {
    pub(super) fn from_lookup(
        get: &dyn Fn(&str) -> Option<String>,
        public_url: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let mode = match get("CC_AUTH_MODE").as_deref().map(str::trim) {
            None | Some("standard") => AuthModeKind::Standard,
            Some("enterprise") => AuthModeKind::Enterprise,
            Some(_) => return err("CC_AUTH_MODE: expected standard or enterprise"),
        };
        let mut c = Self::standard();
        c.mode = mode;
        c.recheck_interval = Duration::from_secs(
            60 * u64::from(parse_or::<u32>(
                get("CC_AUTH_RECHECK_MINUTES"),
                "CC_AUTH_RECHECK_MINUTES",
                15,
            )?),
        );
        c.recheck_grace = Duration::from_secs(
            3600 * u64::from(parse_or::<u32>(
                get("CC_AUTH_RECHECK_GRACE_HOURS"),
                "CC_AUTH_RECHECK_GRACE_HOURS",
                24,
            )?),
        );
        if c.recheck_interval < Duration::from_secs(60)
            || c.recheck_interval > Duration::from_secs(24 * 3600)
        {
            return err("CC_AUTH_RECHECK_MINUTES must be between 1 and 1440");
        }
        if c.recheck_grace > Duration::from_secs(30 * 24 * 3600) {
            return err("CC_AUTH_RECHECK_GRACE_HOURS must be between 0 and 720");
        }
        if mode == AuthModeKind::Standard {
            // Provider settings are ignored (kept so switching back and forth
            // is a one-key change).
            return Ok(c);
        }
        c.provider = Some(match get("CC_AUTH_PROVIDER").as_deref().map(str::trim) {
            Some("oidc") => ProviderKind::Oidc,
            Some("ldap") => ProviderKind::Ldap,
            None => return err("CC_AUTH_MODE=enterprise requires CC_AUTH_PROVIDER=oidc or ldap"),
            Some(_) => return err("CC_AUTH_PROVIDER: expected oidc or ldap"),
        });
        c.display_name = get("CC_AUTH_DISPLAY_NAME").map(|s| s.trim().to_owned());
        if let Some(n) = &c.display_name {
            if n.chars().count() > 64 || n.chars().any(char::is_control) {
                return err("CC_AUTH_DISPLAY_NAME: at most 64 printable characters");
            }
        }
        c.allowed_domains = list(get("CC_AUTH_ALLOWED_DOMAINS"), |ch| {
            ch == ',' || ch.is_whitespace()
        })
        .into_iter()
        .map(|d| d.trim_start_matches('@').to_ascii_lowercase())
        .collect();
        for d in &c.allowed_domains {
            if !d.contains('.') || d.contains('@') || d.starts_with('.') || d.ends_with('.') {
                return err("CC_AUTH_ALLOWED_DOMAINS: expected domains like acme.com");
            }
        }
        c.auto_create = parse_bool(get("CC_AUTH_AUTO_CREATE"), "CC_AUTH_AUTO_CREATE", true)?;
        match c.provider {
            Some(ProviderKind::Oidc) => {
                c.oidc = Some(oidc_from_lookup(get, &c)?);
                match public_url {
                    Some(u) if u.starts_with("https://") || is_loopback_http(u) => {}
                    _ => return err(
                        "OIDC sign-in requires CC_PUBLIC_URL (https://…): the IdP redirects to \
                             CC_PUBLIC_URL/v1/auth/oidc/callback",
                    ),
                }
            }
            Some(ProviderKind::Ldap) => c.ldap = Some(ldap_from_lookup(get)?),
            None => unreachable!("set above"),
        }
        Ok(c)
    }
}

fn oidc_from_lookup(
    get: &dyn Fn(&str) -> Option<String>,
    auth: &AuthConfig,
) -> Result<OidcConfig, ConfigError> {
    let preset = match get("CC_OIDC_PRESET").as_deref().map(str::trim) {
        None | Some("generic") => OidcPreset::Generic,
        Some("entra") => OidcPreset::Entra,
        Some("adfs") => OidcPreset::Adfs,
        Some("keycloak") => OidcPreset::Keycloak,
        Some("google") => OidcPreset::Google,
        Some("okta") => OidcPreset::Okta,
        Some(_) => {
            return err("CC_OIDC_PRESET: expected generic, entra, adfs, keycloak, google or okta")
        }
    };
    let issuer = match (get("CC_OIDC_ISSUER"), preset) {
        (Some(i), _) => i.trim().to_owned(),
        (None, OidcPreset::Google) => "https://accounts.google.com".to_owned(),
        (None, _) => return err("CC_OIDC_ISSUER is required"),
    };
    check_idp_url("CC_OIDC_ISSUER", &issuer)?;
    if issuer.contains(['?', '#']) {
        return err("CC_OIDC_ISSUER must not contain a query or fragment");
    }
    let client_id = get("CC_OIDC_CLIENT_ID")
        .map(|s| s.trim().to_owned())
        .ok_or_else(|| ConfigError("CC_OIDC_CLIENT_ID is required".into()))?;
    let client_secret_file = get("CC_OIDC_CLIENT_SECRET_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| {
            ConfigError(
                "CC_OIDC_CLIENT_SECRET_FILE is required (file with the client secret)".into(),
            )
        })?;
    let token_key_file = get("CC_OIDC_TOKEN_KEY_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| {
            ConfigError(
                "CC_OIDC_TOKEN_KEY_FILE is required (32-byte key sealing IdP refresh tokens; \
                 e.g. `openssl rand -hex 32`)"
                    .into(),
            )
        })?;
    let default_scopes = match preset {
        OidcPreset::Adfs => "openid email profile allatclaims",
        OidcPreset::Google => "openid email profile",
        _ => "openid email profile offline_access",
    };
    let scopes = list(
        Some(get("CC_OIDC_SCOPES").unwrap_or_else(|| default_scopes.to_owned())),
        char::is_whitespace,
    );
    if !scopes.iter().any(|s| s == "openid") {
        return err("CC_OIDC_SCOPES must include openid");
    }
    let email_claim = get("CC_OIDC_EMAIL_CLAIM")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| {
            match preset {
                OidcPreset::Entra => "preferred_username",
                OidcPreset::Adfs => "upn",
                _ => "email",
            }
            .to_owned()
        });
    let required_claim = match get("CC_OIDC_REQUIRED_CLAIM") {
        None => None,
        Some(v) => match v.trim().split_once('=') {
            Some((k, val)) if !k.trim().is_empty() && !val.trim().is_empty() => {
                Some((k.trim().to_owned(), val.trim().to_owned()))
            }
            _ => return err("CC_OIDC_REQUIRED_CLAIM: expected claim=value"),
        },
    };
    let require_mfa = parse_bool(get("CC_OIDC_REQUIRE_MFA"), "CC_OIDC_REQUIRE_MFA", false)?;
    let mfa_acr_values = list(get("CC_OIDC_MFA_ACR_VALUES"), |ch| {
        ch == ',' || ch.is_whitespace()
    });
    let token_auth_method = match get("CC_OIDC_TOKEN_AUTH_METHOD").as_deref().map(str::trim) {
        None | Some("client_secret_basic") | Some("basic") => TokenAuthMethod::Basic,
        Some("client_secret_post") | Some("post") => TokenAuthMethod::Post,
        Some(_) => {
            return err(
                "CC_OIDC_TOKEN_AUTH_METHOD: expected client_secret_basic or client_secret_post",
            )
        }
    };
    let mut extra_auth_params = Vec::new();

    // Preset sanity checks: catch the typical misconfigurations early.
    let path = issuer
        .split_once("://")
        .map(|(_, r)| r)
        .and_then(|r| r.split_once('/'))
        .map(|(_, p)| p.trim_end_matches('/'))
        .unwrap_or("");
    match preset {
        OidcPreset::Entra => {
            let segments: Vec<&str> = path.split('/').collect();
            match segments.as_slice() {
                [tenant, "v2.0"]
                    if !["common", "organizations", "consumers"]
                        .contains(&tenant.to_ascii_lowercase().as_str()) => {}
                [tenant, ..]
                    if ["common", "organizations", "consumers"]
                        .contains(&tenant.to_ascii_lowercase().as_str()) =>
                {
                    return err(
                        "CC_OIDC_ISSUER: Entra ID multi-tenant endpoints (/common, /organizations, \
                         /consumers) are not allowed — use https://login.microsoftonline.com/<tenant-id>/v2.0",
                    )
                }
                _ => {
                    return err(
                        "CC_OIDC_ISSUER: for entra expected https://login.microsoftonline.com/<tenant-id>/v2.0",
                    )
                }
            }
        }
        OidcPreset::Adfs => {
            if !path.ends_with("adfs") {
                return err("CC_OIDC_ISSUER: for adfs expected https://<adfs-host>/adfs");
            }
        }
        OidcPreset::Keycloak => {
            if !path.contains("realms/") {
                return err("CC_OIDC_ISSUER: for keycloak expected https://<host>/realms/<realm>");
            }
        }
        OidcPreset::Google => {
            if issuer != "https://accounts.google.com" {
                return err("CC_OIDC_ISSUER: for google it is https://accounts.google.com");
            }
            if auth.allowed_domains.is_empty() {
                return err(
                    "CC_OIDC_PRESET=google requires CC_AUTH_ALLOWED_DOMAINS (your Workspace \
                     domains); otherwise any Google account could sign in",
                );
            }
            if require_mfa && mfa_acr_values.is_empty() {
                return err(
                    "CC_OIDC_REQUIRE_MFA: Google does not report MFA in ID tokens; enforce \
                     2-Step Verification in the Workspace admin console instead",
                );
            }
            // Google issues refresh tokens only for offline access.
            extra_auth_params.push(("access_type".to_owned(), "offline".to_owned()));
            extra_auth_params.push(("prompt".to_owned(), "consent".to_owned()));
        }
        OidcPreset::Okta | OidcPreset::Generic => {}
    }
    if preset == OidcPreset::Google && scopes.iter().any(|s| s == "offline_access") {
        return err("CC_OIDC_SCOPES: Google rejects offline_access (the preset requests offline access itself)");
    }
    Ok(OidcConfig {
        preset,
        issuer,
        client_id,
        client_secret_file,
        scopes,
        email_claim,
        required_claim,
        require_mfa,
        mfa_acr_values,
        token_key_file,
        token_auth_method,
        ca_file: get("CC_OIDC_CA_FILE").map(PathBuf::from),
        extra_auth_params,
    })
}

pub const DEFAULT_LDAP_USER_FILTER: &str =
    "(&(objectClass=user)(|(mail={login})(userPrincipalName={login})(sAMAccountName={login})))";

fn ldap_from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<LdapConfig, ConfigError> {
    let url = get("CC_LDAP_URL")
        .map(|s| s.trim().to_owned())
        .ok_or_else(|| ConfigError("CC_LDAP_URL is required".into()))?;
    let starttls = parse_bool(get("CC_LDAP_STARTTLS"), "CC_LDAP_STARTTLS", false)?;
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("ldaps://") {
        if starttls {
            return err("CC_LDAP_STARTTLS=true is for ldap:// URLs; ldaps:// is already TLS");
        }
    } else if lower.starts_with("ldap://") {
        if !starttls {
            return err(
                "CC_LDAP_URL: plain ldap:// is refused (passwords would cross the network \
                 unencrypted) — use ldaps:// or set CC_LDAP_STARTTLS=true",
            );
        }
    } else {
        return err("CC_LDAP_URL: expected ldaps://host[:636] or ldap://host[:389] with STARTTLS");
    }
    let bind_dn = get("CC_LDAP_BIND_DN")
        .map(|s| s.trim().to_owned())
        .ok_or_else(|| ConfigError("CC_LDAP_BIND_DN is required (service account)".into()))?;
    let bind_password_file = get("CC_LDAP_BIND_PASSWORD_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| ConfigError("CC_LDAP_BIND_PASSWORD_FILE is required".into()))?;
    let base_dn = get("CC_LDAP_BASE_DN")
        .map(|s| s.trim().to_owned())
        .ok_or_else(|| ConfigError("CC_LDAP_BASE_DN is required".into()))?;
    let user_filter = get("CC_LDAP_USER_FILTER")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| DEFAULT_LDAP_USER_FILTER.to_owned());
    if !user_filter.contains("{login}") || !user_filter.starts_with('(') {
        return err("CC_LDAP_USER_FILTER must be an LDAP filter containing {login}");
    }
    let max_failures = parse_or(get("CC_LDAP_MAX_FAILURES"), "CC_LDAP_MAX_FAILURES", 3u32)?;
    if !(1..=100).contains(&max_failures) {
        return err("CC_LDAP_MAX_FAILURES must be between 1 and 100 (and below the domain lockout threshold)");
    }
    let window = parse_or(
        get("CC_LDAP_FAILURE_WINDOW_MINUTES"),
        "CC_LDAP_FAILURE_WINDOW_MINUTES",
        15u32,
    )?;
    if !(1..=1440).contains(&window) {
        return err("CC_LDAP_FAILURE_WINDOW_MINUTES must be between 1 and 1440");
    }
    let timeout = parse_or(get("CC_LDAP_TIMEOUT_SECS"), "CC_LDAP_TIMEOUT_SECS", 10u64)?;
    if !(1..=60).contains(&timeout) {
        return err("CC_LDAP_TIMEOUT_SECS must be between 1 and 60");
    }
    Ok(LdapConfig {
        url,
        starttls,
        ca_file: get("CC_LDAP_CA_FILE").map(PathBuf::from),
        bind_dn,
        bind_password_file,
        base_dn,
        user_filter,
        email_attr: get("CC_LDAP_EMAIL_ATTR")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "mail".to_owned()),
        id_attr: get("CC_LDAP_ID_ATTR")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "objectGUID".to_owned()),
        required_group: get("CC_LDAP_REQUIRED_GROUP").map(|s| s.trim().to_owned()),
        timeout: Duration::from_secs(timeout),
        max_failures,
        failure_window: Duration::from_secs(60 * u64::from(window)),
        max_failures_per_ip: parse_or(
            get("CC_LDAP_MAX_FAILURES_PER_IP"),
            "CC_LDAP_MAX_FAILURES_PER_IP",
            30u32,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(pairs: &[(&str, &str)]) -> Result<AuthConfig, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let get = |k: &str| map.get(k).cloned();
        AuthConfig::from_lookup(&get, Some("https://sync.acme.test"))
    }

    const OIDC: &[(&str, &str)] = &[
        ("CC_AUTH_MODE", "enterprise"),
        ("CC_AUTH_PROVIDER", "oidc"),
        ("CC_OIDC_CLIENT_ID", "cc"),
        (
            "CC_OIDC_CLIENT_SECRET_FILE",
            "/run/secrets/oidc-client-secret",
        ),
        ("CC_OIDC_TOKEN_KEY_FILE", "/run/secrets/oidc-token-key"),
    ];

    fn oidc(extra: &[(&str, &str)]) -> Result<AuthConfig, ConfigError> {
        let mut v = OIDC.to_vec();
        v.extend_from_slice(extra);
        load(&v)
    }

    #[test]
    fn standard_by_default_ignores_provider_settings() {
        let c = load(&[("CC_OIDC_ISSUER", "garbage")]).unwrap();
        assert!(!c.is_enterprise());
        assert!(c.enterprise_provider().is_none());
        assert!(c.oidc.is_none());
        assert!(load(&[("CC_AUTH_MODE", "sso")]).is_err());
        assert!(load(&[("CC_AUTH_MODE", "enterprise")]).is_err());
    }

    #[test]
    fn oidc_presets_and_sanity_checks() {
        let c = oidc(&[
            ("CC_OIDC_PRESET", "entra"),
            (
                "CC_OIDC_ISSUER",
                "https://login.microsoftonline.com/0b0c1c2d-1111-2222-3333-444455556666/v2.0",
            ),
        ])
        .unwrap();
        let o = c.oidc.unwrap();
        assert_eq!(o.email_claim, "preferred_username");
        assert!(o.scopes.contains(&"offline_access".to_owned()));
        for bad in [
            "https://login.microsoftonline.com/common/v2.0",
            "https://login.microsoftonline.com/organizations/v2.0",
            "https://login.microsoftonline.com/Consumers/v2.0",
            "https://login.microsoftonline.com/tenant",
        ] {
            let e = oidc(&[("CC_OIDC_PRESET", "entra"), ("CC_OIDC_ISSUER", bad)]).unwrap_err();
            assert!(e.to_string().contains("CC_OIDC_ISSUER"), "{bad}: {e}");
        }
        assert!(oidc(&[
            ("CC_OIDC_PRESET", "adfs"),
            ("CC_OIDC_ISSUER", "https://adfs.acme.test/adfs")
        ])
        .unwrap()
        .oidc
        .unwrap()
        .scopes
        .contains(&"allatclaims".to_owned()));
        assert!(oidc(&[
            ("CC_OIDC_PRESET", "keycloak"),
            ("CC_OIDC_ISSUER", "https://kc.acme.test/auth")
        ])
        .is_err());
        // Google needs the Workspace domain list and gets offline access.
        assert!(oidc(&[("CC_OIDC_PRESET", "google")]).is_err());
        let g = oidc(&[
            ("CC_OIDC_PRESET", "google"),
            ("CC_AUTH_ALLOWED_DOMAINS", "acme.test"),
        ])
        .unwrap()
        .oidc
        .unwrap();
        assert_eq!(g.issuer, "https://accounts.google.com");
        assert!(g
            .extra_auth_params
            .contains(&("access_type".into(), "offline".into())));
        assert!(oidc(&[
            ("CC_OIDC_PRESET", "google"),
            ("CC_AUTH_ALLOWED_DOMAINS", "acme.test"),
            ("CC_OIDC_REQUIRE_MFA", "true")
        ])
        .is_err());
    }

    #[test]
    fn oidc_requires_https_secrets_and_public_url() {
        assert!(oidc(&[("CC_OIDC_ISSUER", "http://idp.acme.test")]).is_err());
        assert!(oidc(&[("CC_OIDC_ISSUER", "http://127.0.0.1:8080/realms/x")]).is_ok());
        assert!(oidc(&[("CC_OIDC_ISSUER", "https://idp.acme.test?x=1")]).is_err());
        let mut no_key = OIDC.to_vec();
        no_key.retain(|(k, _)| *k != "CC_OIDC_TOKEN_KEY_FILE");
        no_key.push(("CC_OIDC_ISSUER", "https://idp.acme.test"));
        assert!(load(&no_key).is_err());
        let map: HashMap<String, String> = OIDC
            .iter()
            .chain([("CC_OIDC_ISSUER", "https://idp.acme.test")].iter())
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let get = |k: &str| map.get(k).cloned();
        assert!(AuthConfig::from_lookup(&get, None).is_err());
        assert!(AuthConfig::from_lookup(&get, Some("http://sync.acme.test")).is_err());
        let c = oidc(&[
            ("CC_OIDC_ISSUER", "https://idp.acme.test"),
            ("CC_OIDC_REQUIRED_CLAIM", "groups=cc-users"),
            ("CC_AUTH_ALLOWED_DOMAINS", "Acme.test, @acme.ru"),
        ])
        .unwrap();
        assert_eq!(c.allowed_domains, ["acme.test", "acme.ru"]);
        assert!(c.domain_allowed("Bob@ACME.test"));
        assert!(!c.domain_allowed("bob@acme.test.evil.example"));
        assert!(!c.domain_allowed("bob@sub.acme.test"));
        assert_eq!(
            c.oidc.unwrap().required_claim,
            Some(("groups".into(), "cc-users".into()))
        );
        assert!(oidc(&[
            ("CC_OIDC_ISSUER", "https://idp.acme.test"),
            ("CC_OIDC_REQUIRED_CLAIM", "groups")
        ])
        .is_err());
    }

    const LDAP: &[(&str, &str)] = &[
        ("CC_AUTH_MODE", "enterprise"),
        ("CC_AUTH_PROVIDER", "ldap"),
        ("CC_LDAP_BIND_DN", "CN=svc,DC=acme,DC=local"),
        (
            "CC_LDAP_BIND_PASSWORD_FILE",
            "/run/secrets/ldap-bind-password",
        ),
        ("CC_LDAP_BASE_DN", "DC=acme,DC=local"),
    ];

    fn ldap(extra: &[(&str, &str)]) -> Result<AuthConfig, ConfigError> {
        let mut v = LDAP.to_vec();
        v.extend_from_slice(extra);
        load(&v)
    }

    #[test]
    fn plain_ldap_is_refused() {
        let e = ldap(&[("CC_LDAP_URL", "ldap://dc1.acme.local:389")]).unwrap_err();
        assert!(e.to_string().contains("plain ldap://"), "{e}");
        assert!(ldap(&[
            ("CC_LDAP_URL", "ldap://dc1.acme.local:389"),
            ("CC_LDAP_STARTTLS", "true")
        ])
        .is_ok());
        assert!(ldap(&[
            ("CC_LDAP_URL", "ldaps://dc1.acme.local"),
            ("CC_LDAP_STARTTLS", "true")
        ])
        .is_err());
        assert!(ldap(&[("CC_LDAP_URL", "http://dc1.acme.local")]).is_err());
        let c = ldap(&[("CC_LDAP_URL", "ldaps://dc1.acme.local:636")]).unwrap();
        let l = c.ldap.unwrap();
        assert_eq!(l.id_attr, "objectGUID");
        assert_eq!(l.max_failures, 3);
        assert_eq!(l.failure_window, Duration::from_secs(900));
        assert!(ldap(&[
            ("CC_LDAP_URL", "ldaps://dc1"),
            ("CC_LDAP_USER_FILTER", "(mail=x)")
        ])
        .is_err());
        assert!(ldap(&[
            ("CC_LDAP_URL", "ldaps://dc1"),
            ("CC_LDAP_MAX_FAILURES", "0")
        ])
        .is_err());
    }

    #[test]
    fn recheck_bounds() {
        assert!(load(&[("CC_AUTH_RECHECK_MINUTES", "0")]).is_err());
        assert!(load(&[("CC_AUTH_RECHECK_GRACE_HOURS", "721")]).is_err());
        let c = load(&[("CC_AUTH_RECHECK_MINUTES", "5")]).unwrap();
        assert_eq!(c.recheck_interval, Duration::from_secs(300));
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_http("http://127.0.0.1:58080/realms/x"));
        assert!(is_loopback_http("http://localhost/x"));
        assert!(is_loopback_http("http://[::1]:80/"));
        assert!(!is_loopback_http("http://127.0.0.1.evil.example/"));
        assert!(!is_loopback_http("http://localhost.evil.example:80/"));
        assert!(!is_loopback_http("https://127.0.0.1/"));
    }
}
