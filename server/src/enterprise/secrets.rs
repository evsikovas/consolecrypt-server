// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Secrets of the enterprise providers (ТР-8): read from files (Kubernetes
//! Secret / Docker secret mounts), never from the environment or logs, and
//! the upstream-token sealing box.
//!
//! [`TokenBox`] seals the IdP refresh tokens kept for re-checks
//! (ChaCha20-Poly1305, random nonce, the identity as associated data). It
//! protects *upstream* IdP credentials at rest only; it has nothing to do with
//! vault data, which the server still cannot decrypt.

use base64::Engine as _;
use cc_protocol::auth::SecretString;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::fmt;
use std::io::Read as _;
use std::path::Path;

const MAX_SECRET_FILE: u64 = 64 * 1024;
const SEALED_VERSION: u8 = 1;

/// Read a secret file (trailing newline removed). Errors name the file and
/// the problem, never its content.
pub fn read_secret_file(what: &str, path: &Path) -> anyhow::Result<SecretString> {
    let bytes = read_bytes(what, path)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("{what} ({}): not UTF-8 text", path.display()))?;
    let value = text.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() {
        anyhow::bail!("{what} ({}): file is empty", path.display());
    }
    Ok(SecretString::new(value))
}

pub fn read_bytes(what: &str, path: &Path) -> anyhow::Result<Vec<u8>> {
    let fail = |m: &str| anyhow::anyhow!("{what} ({}): {m}", path.display());
    let file = std::fs::File::open(path).map_err(|_| fail("cannot open the file"))?;
    let meta = file.metadata().map_err(|_| fail("cannot read the file"))?;
    if !meta.is_file() {
        return Err(fail("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("cannot read the file"))?;
    if bytes.len() as u64 > MAX_SECRET_FILE {
        return Err(fail("file too large"));
    }
    Ok(bytes)
}

/// AEAD box for upstream refresh tokens.
pub struct TokenBox {
    key: LessSafeKey,
}

impl fmt::Debug for TokenBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenBox(<redacted>)")
    }
}

impl TokenBox {
    /// Key file: 32 raw random bytes, 64 hex characters or base64 of 32 bytes.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let raw = read_bytes("CC_OIDC_TOKEN_KEY_FILE", path)?;
        let key = parse_key(&raw).ok_or_else(|| {
            anyhow::anyhow!(
                "CC_OIDC_TOKEN_KEY_FILE ({}): expected 32 random bytes, as raw bytes, 64 hex \
                 characters or base64 (e.g. `openssl rand -hex 32`)",
                path.display()
            )
        })?;
        Ok(Self::new(&key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte key")),
        }
    }

    /// `version || nonce || ciphertext+tag`, bound to `context`.
    pub fn seal(&self, context: &[u8], plaintext: &str) -> Vec<u8> {
        let nonce_bytes = crate::crypto::random_bytes::<12>();
        let mut buf = plaintext.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(context),
                &mut buf,
            )
            .expect("sealing a bounded token cannot fail");
        let mut out = Vec::with_capacity(1 + 12 + buf.len());
        out.push(SEALED_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        out
    }

    /// `None` when the box was sealed with another key or context, or is
    /// corrupt (the token is then treated as missing).
    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Option<SecretString> {
        if sealed.len() < 1 + 12 + aead::MAX_TAG_LEN || sealed[0] != SEALED_VERSION {
            return None;
        }
        let nonce = Nonce::try_assume_unique_for_key(&sealed[1..13]).ok()?;
        let mut buf = sealed[13..].to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(context), &mut buf)
            .ok()?;
        String::from_utf8(plain.to_vec())
            .ok()
            .map(SecretString::new)
    }
}

fn parse_key(raw: &[u8]) -> Option<[u8; 32]> {
    // 32 raw random bytes (a 32-character *text* is not a key: too little
    // entropy, and probably a mistake).
    if raw.len() == 32 && raw.iter().any(|b| !(0x20..0x7f).contains(b)) {
        return raw.try_into().ok();
    }
    let text = std::str::from_utf8(raw).ok()?.trim();
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, chunk) in text.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        }
        return Some(out);
    }
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        if let Ok(bytes) = engine.decode(text) {
            if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Some(key);
            }
        }
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_is_bound_to_key_and_context() {
        let b = TokenBox::new(&[7u8; 32]);
        let sealed = b.seal(b"oidc|iss|sub", "refresh-token-value");
        assert!(!sealed
            .windows(b"refresh-token-value".len())
            .any(|w| w == b"refresh-token-value"));
        assert_eq!(
            b.open(b"oidc|iss|sub", &sealed).unwrap().expose_secret(),
            "refresh-token-value"
        );
        assert!(b.open(b"oidc|iss|other", &sealed).is_none());
        assert!(TokenBox::new(&[8u8; 32])
            .open(b"oidc|iss|sub", &sealed)
            .is_none());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(b.open(b"oidc|iss|sub", &tampered).is_none());
        assert!(b.open(b"oidc|iss|sub", &[1, 2, 3]).is_none());
        assert_ne!(sealed, b.seal(b"oidc|iss|sub", "refresh-token-value"));
        assert_eq!(format!("{b:?}"), "TokenBox(<redacted>)");
    }

    #[test]
    fn key_formats() {
        let hex = "00".repeat(31) + "ff";
        assert_eq!(parse_key(hex.as_bytes()).unwrap()[31], 0xff);
        assert_eq!(parse_key(format!("{hex}\n").as_bytes()).unwrap()[31], 0xff);
        let b64 = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        assert_eq!(parse_key(b64.as_bytes()).unwrap(), [9u8; 32]);
        assert_eq!(parse_key(&[5u8; 32]).unwrap(), [5u8; 32]);
        assert!(parse_key(&[b'a'; 32]).is_none());
        assert!(parse_key(b"short").is_none());
        assert!(parse_key("00".repeat(16).as_bytes()).is_none());
    }

    #[test]
    fn secret_file_errors_do_not_echo_content() {
        let dir = std::env::temp_dir().join(format!("cc-secret-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("s");
        std::fs::write(&path, b"top-secret-value\n").unwrap();
        assert_eq!(
            read_secret_file("X", &path).unwrap().expose_secret(),
            "top-secret-value"
        );
        std::fs::write(&path, [0xffu8, 0xfe, b's']).unwrap();
        let e = read_secret_file("X", &path).unwrap_err().to_string();
        assert!(e.contains("UTF-8"));
        std::fs::write(&path, b"\n").unwrap();
        assert!(read_secret_file("X", &path).is_err());
        assert!(read_secret_file("X", &dir).is_err());
        assert!(read_secret_file("X", &dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
