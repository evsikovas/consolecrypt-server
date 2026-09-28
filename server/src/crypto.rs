// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! The complete set of cryptographic operations the server performs.
//!
//! * random opaque tokens and their SHA-256 hashes;
//! * constant-time comparison;
//! * Argon2id hashing of *account* passwords;
//! * the vault access key (VAK) verifier: `SHA-256(VAK)` (ADR-0002);
//! * Ed25519 signature **verification** of device approvals (ADR-0004).
//!
//! There is deliberately no symmetric decryption, no key agreement and no
//! key derivation from vault material here: the server cannot open vault
//! objects or key envelopes, and adding such code is a design violation
//! (see `docs/security/THREAT_MODEL.md`).

use crate::config::PasswordHashingConfig;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cc_protocol::auth::SecretString;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

/// Fill an array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Constant-time equality (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Kinds of opaque bearer tokens. The prefix makes leaked tokens easy to
/// detect by secret scanners and prevents using one kind as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
    /// Single-use account tokens (password reset, email verification).
    Account,
}

impl TokenKind {
    const fn prefix(self) -> &'static str {
        match self {
            TokenKind::Access => "cca_",
            TokenKind::Refresh => "ccr_",
            TokenKind::Account => "cct_",
        }
    }
}

/// Length of base64url(32 bytes) without padding.
const TOKEN_BODY_LEN: usize = 43;

/// A freshly issued token: the secret goes to the client once, only the hash
/// is stored.
pub struct IssuedToken {
    pub token: SecretString,
    pub hash: [u8; 32],
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedToken(<redacted>)")
    }
}

pub fn issue_token(kind: TokenKind) -> IssuedToken {
    let token = format!(
        "{}{}",
        kind.prefix(),
        URL_SAFE_NO_PAD.encode(random_bytes::<32>())
    );
    let hash = sha256(token.as_bytes());
    IssuedToken {
        token: SecretString::new(token),
        hash,
    }
}

/// Hash a presented token after checking its shape. `None` for anything that
/// cannot be a token of `kind` (no DB lookup needed).
pub fn presented_token_hash(kind: TokenKind, presented: &str) -> Option<[u8; 32]> {
    let body = presented.strip_prefix(kind.prefix())?;
    if body.len() != TOKEN_BODY_LEN
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(sha256(presented.as_bytes()))
}

/// `SHA-256(vault_access_key)` as stored in `vaults.access_key_verifier`.
pub fn vault_access_key_verifier(vak: &[u8]) -> [u8; 32] {
    sha256(vak)
}

/// Constant-time check of a presented vault access key against the verifier.
pub fn verify_vault_access_key(vak: &[u8], verifier: &[u8]) -> bool {
    vak.len() == cc_protocol::limits::VAULT_ACCESS_KEY_LEN
        && ct_eq(&vault_access_key_verifier(vak), verifier)
}

/// A well-formed, non-weak Ed25519 public key.
pub fn is_valid_signing_public_key(key: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_ok_and(|k| !k.is_weak())
}

/// A 32-byte X25519 public key that is not all zeros. (Low-order points are
/// rejected by clients when they compute the shared secret.)
pub fn is_valid_encryption_public_key(key: &[u8]) -> bool {
    key.len() == cc_protocol::limits::X25519_PUBLIC_KEY_LEN && key.iter().any(|b| *b != 0)
}

/// Strict Ed25519 verification (rejects malleable / small-order inputs).
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    vk.verify_strict(message, &sig).is_ok()
}

/// Argon2id hashing of account passwords, off the async runtime and bounded
/// by a semaphore so a login flood cannot exhaust CPU/memory.
#[derive(Clone)]
pub struct PasswordHasher {
    params: Params,
    permits: Arc<Semaphore>,
    /// Hash of a random password, verified when the account does not exist so
    /// timing does not reveal registered emails.
    dummy_hash: Arc<str>,
}

impl fmt::Debug for PasswordHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHasher")
            .field("m_cost", &self.params.m_cost())
            .field("t_cost", &self.params.t_cost())
            .finish_non_exhaustive()
    }
}

impl PasswordHasher {
    pub fn new(cfg: &PasswordHashingConfig) -> anyhow::Result<Self> {
        let params = Params::new(cfg.memory_kib, cfg.iterations, cfg.parallelism, None)
            .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
        let dummy_hash = argon
            .hash_password(&random_bytes::<32>())
            .map_err(|e| anyhow::anyhow!("argon2: {e}"))?
            .to_string();
        Ok(Self {
            params,
            permits: Arc::new(Semaphore::new(cfg.max_concurrent.max(1))),
            dummy_hash: dummy_hash.into(),
        })
    }

    fn argon(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }

    /// Wait at most this long for a hashing slot, then shed load (503).
    const QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    async fn permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, HasherBusy> {
        match tokio::time::timeout(Self::QUEUE_TIMEOUT, self.permits.acquire()).await {
            Ok(Ok(p)) => Ok(p),
            _ => {
                metrics::counter!("cc_password_hasher_busy_total").increment(1);
                Err(HasherBusy)
            }
        }
    }

    /// Hash a password into a PHC string.
    pub async fn hash(&self, password: &SecretString) -> Result<String, HashError> {
        let _permit = self.permit().await?;
        let argon = self.argon();
        let pw = password.clone();
        tokio::task::spawn_blocking(move || {
            argon
                .hash_password(pw.expose_secret().as_bytes())
                .map(|h| h.to_string())
                .map_err(|e| HashError::Internal(anyhow::anyhow!("argon2: {e}")))
        })
        .await
        .map_err(|e| HashError::Internal(e.into()))?
    }

    /// Verify `password` against `phc`; with `None` a dummy hash is verified
    /// (and `false` returned) to keep timing uniform. `Err` when every hashing
    /// slot stayed busy for the queue timeout (load shedding).
    pub async fn verify(
        &self,
        password: &SecretString,
        phc: Option<&str>,
    ) -> Result<bool, HasherBusy> {
        let _permit = self.permit().await?;
        let known = phc.is_some();
        let phc: String = phc.unwrap_or(&self.dummy_hash).to_owned();
        let pw = password.clone();
        let argon = self.argon();
        let ok = tokio::task::spawn_blocking(move || {
            PasswordHash::new(&phc)
                .map(|parsed| {
                    argon
                        .verify_password(pw.expose_secret().as_bytes(), &parsed)
                        .is_ok()
                })
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        Ok(ok && known)
    }
}

/// All hashing slots stayed busy for the queue timeout.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("password hashing is saturated")]
pub struct HasherBusy;

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error(transparent)]
    Busy(#[from] HasherBusy),
    #[error("{0}")]
    Internal(anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn tokens_roundtrip_and_are_kind_bound() {
        let t = issue_token(TokenKind::Access);
        let s = t.token.expose_secret();
        assert!(s.starts_with("cca_"));
        assert_eq!(presented_token_hash(TokenKind::Access, s), Some(t.hash));
        assert_eq!(presented_token_hash(TokenKind::Refresh, s), None);
        assert_eq!(presented_token_hash(TokenKind::Access, "cca_short"), None);
        assert_eq!(
            presented_token_hash(TokenKind::Access, &format!("{s}x")),
            None
        );
        assert!(!format!("{t:?}").contains(&s[4..]));
    }

    #[test]
    fn vak_verifier_is_constant_time_equal() {
        let vak = random_bytes::<32>();
        let verifier = vault_access_key_verifier(&vak);
        assert!(verify_vault_access_key(&vak, &verifier));
        let mut wrong = vak;
        wrong[0] ^= 1;
        assert!(!verify_vault_access_key(&wrong, &verifier));
        assert!(!verify_vault_access_key(&vak[..31], &verifier));
    }

    #[test]
    fn ed25519_verification() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&random_bytes::<32>());
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(b"message").to_bytes();
        assert!(is_valid_signing_public_key(&pk));
        assert!(verify_ed25519(&pk, b"message", &sig));
        assert!(!verify_ed25519(&pk, b"other", &sig));
        assert!(!verify_ed25519(&pk, b"message", &sig[..63]));
        // Small-order points (identity) are rejected.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!is_valid_signing_public_key(&identity));
        assert!(!is_valid_signing_public_key(&pk[..31]));
    }

    #[test]
    fn encryption_key_shape() {
        assert!(is_valid_encryption_public_key(&[1u8; 32]));
        assert!(!is_valid_encryption_public_key(&[0u8; 32]));
        assert!(!is_valid_encryption_public_key(&[1u8; 31]));
    }

    #[tokio::test]
    async fn password_hash_and_verify() {
        let h = PasswordHasher::new(&PasswordHashingConfig {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
            max_concurrent: 2,
        })
        .unwrap();
        let pw = SecretString::new("correct horse battery staple");
        let phc = h.hash(&pw).await.unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(h.verify(&pw, Some(&phc)).await.unwrap());
        assert!(!h
            .verify(&SecretString::new("wrong password!!"), Some(&phc))
            .await
            .unwrap());
        assert!(!h.verify(&pw, None).await.unwrap());
        assert!(!h.verify(&pw, Some("not a phc string")).await.unwrap());
    }
}
