// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! LDAP / Active Directory sign-in (ТР-5): search with the service account,
//! then bind as the user with the entered password. TLS only (ldaps:// or
//! STARTTLS, rustls); plain ldap:// is refused at configuration time.
//!
//! * The password is never stored or logged; an empty password is refused
//!   before the directory is contacted (it would be an anonymous bind).
//! * Disabled AD accounts (`userAccountControl` bit 2) are refused.
//! * The required group is checked with `LDAP_MATCHING_RULE_IN_CHAIN`
//!   (`1.2.840.113556.1.4.1941`), so nested membership counts.
//! * The stable id is `objectGUID` (formatted as a GUID string); the email is
//!   only an attribute.

use super::secrets::{read_bytes, read_secret_file};
use crate::config::LdapConfig;
use cc_protocol::auth::SecretString;
use ldap3::{
    ldap_escape, Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions,
};
use std::fmt;
use std::sync::Arc;

/// AD `LDAP_MATCHING_RULE_IN_CHAIN`.
const IN_CHAIN: &str = "1.2.840.113556.1.4.1941";
/// `userAccountControl` ACCOUNTDISABLE.
const UAC_ACCOUNTDISABLE: u32 = 0x2;
const RC_SUCCESS: u32 = 0;
const RC_SIZE_LIMIT: u32 = 4;
const RC_REFERRAL: u32 = 10;
const RC_INVALID_CREDENTIALS: u32 = 49;

/// The directory could not be used (network, TLS, timeout, service bind,
/// unexpected result). Never the user's fault; never counts as a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable(pub &'static str);

/// A directory user found by the service account.
#[derive(Clone, PartialEq, Eq)]
pub struct DirUser {
    pub dn: String,
    /// Stable id (GUID string for `objectGUID`).
    pub subject: String,
    pub email: Option<String>,
    pub disabled: bool,
    /// Member (possibly nested) of the required group, or no group required.
    pub in_group: bool,
}

impl fmt::Debug for DirUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirUser")
            .field("subject", &self.subject)
            .field("disabled", &self.disabled)
            .field("in_group", &self.in_group)
            .finish_non_exhaustive()
    }
}

pub struct LdapProvider {
    pub cfg: LdapConfig,
    bind_password: SecretString,
    tls: Arc<rustls::ClientConfig>,
    /// `account_identities.issuer` of this directory.
    pub issuer: String,
}

impl fmt::Debug for LdapProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapProvider")
            .field("url", &self.cfg.url)
            .field("base_dn", &self.cfg.base_dn)
            .finish_non_exhaustive()
    }
}

/// Identity issuer string of a directory (its base DN, case-insensitive).
pub fn issuer_for(cfg: &LdapConfig) -> String {
    format!(
        "ldap:{}",
        cfg.base_dn.to_ascii_lowercase().replace(", ", ",")
    )
}

fn tls_config(cfg: &LdapConfig) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    match &cfg.ca_file {
        Some(path) => {
            let pem = read_bytes("CC_LDAP_CA_FILE", path)?;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                let cert = cert.map_err(|_| {
                    anyhow::anyhow!(
                        "CC_LDAP_CA_FILE ({}): invalid PEM certificate",
                        path.display()
                    )
                })?;
                roots.add(cert).map_err(|_| {
                    anyhow::anyhow!("CC_LDAP_CA_FILE ({}): unusable certificate", path.display())
                })?;
            }
            if roots.is_empty() {
                anyhow::bail!("CC_LDAP_CA_FILE ({}): no certificate found", path.display());
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                anyhow::bail!(
                    "LDAP TLS: no system root certificates found; set CC_LDAP_CA_FILE to the \
                     directory's CA certificate"
                );
            }
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| anyhow::anyhow!("LDAP TLS: cannot initialise rustls"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Strip a `DOMAIN\` prefix (the filter matches `sAMAccountName`).
fn login_name(login: &str) -> &str {
    match login.rsplit_once('\\') {
        Some((_, name)) => name,
        None => login,
    }
}

/// AD `objectGUID` bytes → canonical GUID string (mixed endian).
pub fn format_guid(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// GUID string → `objectGUID` bytes.
pub fn parse_guid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut v = [0u8; 16];
    for (i, item) in v.iter_mut().enumerate() {
        *item = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some([
        v[3], v[2], v[1], v[0], v[5], v[4], v[7], v[6], v[8], v[9], v[10], v[11], v[12], v[13],
        v[14], v[15],
    ])
}

/// RFC 4515 escaping of raw bytes (`\xx` for each byte).
fn escape_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("\\{x:02x}")).collect()
}

impl LdapProvider {
    /// Read secrets, build TLS and validate connection + service bind (§3.5).
    pub async fn connect(cfg: &LdapConfig) -> anyhow::Result<Self> {
        let bind_password =
            read_secret_file("CC_LDAP_BIND_PASSWORD_FILE", &cfg.bind_password_file)?;
        let provider = Self {
            cfg: cfg.clone(),
            bind_password,
            tls: tls_config(cfg)?,
            issuer: issuer_for(cfg),
        };
        provider.check().await?;
        Ok(provider)
    }

    /// Connect, TLS, service bind, base DN and group DN exist.
    pub async fn check(&self) -> anyhow::Result<String> {
        let mut ldap = self
            .service()
            .await
            .map_err(|Unavailable(why)| anyhow::anyhow!("LDAP {}: {why}", self.cfg.url))?;
        let base = self
            .search(
                &mut ldap,
                &self.cfg.base_dn,
                Scope::Base,
                "(objectClass=*)",
                &["1.1"],
            )
            .await
            .map_err(|Unavailable(why)| {
                anyhow::anyhow!("LDAP base DN {:?}: {why}", self.cfg.base_dn)
            })?;
        if base.is_empty() {
            anyhow::bail!("LDAP base DN {:?} not found", self.cfg.base_dn);
        }
        if let Some(group) = &self.cfg.required_group {
            let found = self
                .search(&mut ldap, group, Scope::Base, "(objectClass=*)", &["1.1"])
                .await
                .map_err(|Unavailable(why)| anyhow::anyhow!("LDAP group {group:?}: {why}"))?;
            if found.is_empty() {
                anyhow::bail!("CC_LDAP_REQUIRED_GROUP {group:?} not found");
            }
        }
        let _ = ldap.unbind().await;
        Ok(format!(
            "connected to {} ({}), service account bind ok",
            self.cfg.url,
            if self.cfg.starttls {
                "STARTTLS"
            } else {
                "LDAPS"
            }
        ))
    }

    async fn open(&self) -> Result<Ldap, Unavailable> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.cfg.timeout)
            .set_starttls(self.cfg.starttls)
            .set_config(self.tls.clone());
        let (conn, ldap) = tokio::time::timeout(
            self.cfg.timeout,
            LdapConnAsync::with_settings(settings, &self.cfg.url),
        )
        .await
        .map_err(|_| Unavailable("connection timed out"))?
        .map_err(|e| {
            tracing::debug!(error = %e, "LDAP connection failure details");
            Unavailable("cannot connect (network or TLS certificate problem)")
        })?;
        ldap3::drive!(conn);
        Ok(ldap)
    }

    /// A connection bound as the service account.
    async fn service(&self) -> Result<Ldap, Unavailable> {
        let mut ldap = self.open().await?;
        let res = tokio::time::timeout(
            self.cfg.timeout,
            ldap.simple_bind(&self.cfg.bind_dn, self.bind_password.expose_secret()),
        )
        .await
        .map_err(|_| Unavailable("service account bind timed out"))?
        .map_err(|_| Unavailable("service account bind failed"))?;
        if res.rc != RC_SUCCESS {
            tracing::warn!(rc = res.rc, "LDAP service account bind rejected");
            return Err(Unavailable(
                "service account bind rejected (check CC_LDAP_BIND_DN and password)",
            ));
        }
        Ok(ldap)
    }

    async fn search(
        &self,
        ldap: &mut Ldap,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, Unavailable> {
        ldap.with_search_options(SearchOptions::new().sizelimit(2))
            .with_timeout(self.cfg.timeout);
        let result = tokio::time::timeout(
            self.cfg.timeout,
            ldap.search(base, scope, filter, attrs.to_vec()),
        )
        .await
        .map_err(|_| Unavailable("search timed out"))?
        .map_err(|_| Unavailable("search failed"))?;
        let ldap3::SearchResult(entries, res) = result;
        match res.rc {
            RC_SUCCESS | RC_SIZE_LIMIT | RC_REFERRAL => {}
            // noSuchObject: the base does not exist.
            32 => return Ok(Vec::new()),
            rc => {
                tracing::warn!(rc, "LDAP search rejected");
                return Err(Unavailable("search rejected"));
            }
        }
        Ok(entries
            .into_iter()
            .filter(|e| !e.is_ref() && !e.is_intermediate())
            .map(SearchEntry::construct)
            .collect())
    }

    fn first_value(entry: &SearchEntry, attr: &str) -> Option<Vec<u8>> {
        entry
            .bin_attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(attr))
            .and_then(|(_, v)| v.first().cloned())
            .or_else(|| {
                entry
                    .attrs
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(attr))
                    .and_then(|(_, v)| v.first().map(|s| s.as_bytes().to_vec()))
            })
    }

    fn subject_of(&self, entry: &SearchEntry) -> Option<String> {
        let raw = Self::first_value(entry, &self.cfg.id_attr)?;
        if self.cfg.id_attr.eq_ignore_ascii_case("objectGUID") {
            format_guid(&raw)
        } else {
            String::from_utf8(raw)
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty() && s.len() <= 1024)
        }
    }

    fn attrs(&self) -> Vec<&str> {
        vec![
            self.cfg.id_attr.as_str(),
            self.cfg.email_attr.as_str(),
            "userAccountControl",
        ]
    }

    async fn to_user(
        &self,
        ldap: &mut Ldap,
        entry: SearchEntry,
    ) -> Result<Option<DirUser>, Unavailable> {
        let Some(subject) = self.subject_of(&entry) else {
            tracing::warn!("LDAP entry without a usable CC_LDAP_ID_ATTR value; refusing");
            return Ok(None);
        };
        let email = Self::first_value(&entry, &self.cfg.email_attr)
            .and_then(|v| String::from_utf8(v).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| s.contains('@'));
        let uac = Self::first_value(&entry, "userAccountControl")
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .map(|v| v as u32)
            .unwrap_or(0);
        let in_group = match &self.cfg.required_group {
            None => true,
            Some(group) => {
                let filter = format!("(memberOf:{IN_CHAIN}:={})", ldap_escape(group.as_str()));
                !self
                    .search(ldap, &entry.dn, Scope::Base, &filter, &["1.1"])
                    .await?
                    .is_empty()
            }
        };
        Ok(Some(DirUser {
            dn: entry.dn,
            subject,
            email,
            disabled: uac & UAC_ACCOUNTDISABLE != 0,
            in_group,
        }))
    }

    /// Find the user a login names (service account; no user bind, so this
    /// never counts towards the directory's lockout). `None` when there is no
    /// such user or the login is ambiguous.
    pub async fn find_user(&self, login: &str) -> Result<Option<DirUser>, Unavailable> {
        let mut ldap = self.service().await?;
        let filter = self
            .cfg
            .user_filter
            .replace("{login}", &ldap_escape(login_name(login)));
        let mut found = self
            .search(
                &mut ldap,
                &self.cfg.base_dn,
                Scope::Subtree,
                &filter,
                &self.attrs(),
            )
            .await?;
        let user = if found.len() == 1 {
            let entry = found.remove(0);
            self.to_user(&mut ldap, entry).await?
        } else {
            if found.len() > 1 {
                tracing::warn!("LDAP login matches several directory entries; refusing");
            }
            None
        };
        let _ = ldap.unbind().await;
        Ok(user)
    }

    /// Re-check (ТР-6): the user with this stable id, as the service account
    /// sees it now. `None` = deleted (or moved out of the base DN).
    pub async fn lookup_subject(&self, subject: &str) -> Result<Option<DirUser>, Unavailable> {
        let value = if self.cfg.id_attr.eq_ignore_ascii_case("objectGUID") {
            match parse_guid(subject) {
                Some(b) => escape_bytes(&b),
                None => return Ok(None),
            }
        } else {
            ldap_escape(subject).into_owned()
        };
        let filter = format!("({}={value})", self.cfg.id_attr);
        let mut ldap = self.service().await?;
        let mut found = self
            .search(
                &mut ldap,
                &self.cfg.base_dn,
                Scope::Subtree,
                &filter,
                &self.attrs(),
            )
            .await?;
        let user = if found.len() == 1 {
            let entry = found.remove(0);
            self.to_user(&mut ldap, entry).await?
        } else {
            None
        };
        let _ = ldap.unbind().await;
        Ok(user)
    }

    /// Bind as the user. `Ok(false)` = rejected credentials (wrong password,
    /// disabled, expired or locked — indistinguishable on purpose).
    pub async fn verify_password(
        &self,
        user: &DirUser,
        password: &SecretString,
    ) -> Result<bool, Unavailable> {
        if password.expose_secret().is_empty() {
            return Ok(false);
        }
        let mut ldap = self.open().await?;
        let res = tokio::time::timeout(
            self.cfg.timeout,
            ldap.simple_bind(&user.dn, password.expose_secret()),
        )
        .await
        .map_err(|_| Unavailable("user bind timed out"))?
        .map_err(|_| Unavailable("user bind failed"))?;
        let _ = ldap.unbind().await;
        match res.rc {
            RC_SUCCESS => Ok(true),
            RC_INVALID_CREDENTIALS => Ok(false),
            rc => {
                tracing::warn!(rc, "LDAP user bind rejected with an unexpected result");
                Err(Unavailable("user bind rejected"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roundtrip_uses_ad_byte_order() {
        // objectGUID bytes as AD stores them for {01020304-0506-0708-090a-0b0c0d0e0f10}.
        let bytes = [4u8, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16];
        let s = format_guid(&bytes).unwrap();
        assert_eq!(s, "01020304-0506-0708-090a-0b0c0d0e0f10");
        assert_eq!(parse_guid(&s).unwrap(), bytes);
        assert_eq!(parse_guid(&s.to_uppercase()).unwrap(), bytes);
        assert!(format_guid(&bytes[..15]).is_none());
        assert!(parse_guid("not-a-guid").is_none());
        assert_eq!(escape_bytes(&[0, 0x2a, 0xff]), "\\00\\2a\\ff");
    }

    #[test]
    fn login_filter_input_is_escaped() {
        assert_eq!(login_name("CCTEST\\alice"), "alice");
        assert_eq!(login_name("alice@acme.test"), "alice@acme.test");
        let filter = crate::config::DEFAULT_LDAP_USER_FILTER
            .replace("{login}", &ldap_escape(login_name("*)(objectClass=*")));
        assert!(!filter.contains("(objectClass=*)(") && filter.contains("\\2a\\29\\28"));
    }

    #[test]
    fn issuer_is_case_insensitive() {
        let l = |base: &str| crate::config::LdapConfig {
            url: "ldaps://dc".into(),
            starttls: false,
            ca_file: None,
            bind_dn: "x".into(),
            bind_password_file: "x".into(),
            base_dn: base.into(),
            user_filter: "(uid={login})".into(),
            email_attr: "mail".into(),
            id_attr: "objectGUID".into(),
            required_group: None,
            timeout: std::time::Duration::from_secs(1),
            max_failures: 3,
            failure_window: std::time::Duration::from_secs(60),
            max_failures_per_ip: 0,
        };
        assert_eq!(issuer_for(&l("DC=Acme, DC=Local")), "ldap:dc=acme,dc=local");
        assert_eq!(issuer_for(&l("dc=acme,dc=local")), "ldap:dc=acme,dc=local");
    }
}
