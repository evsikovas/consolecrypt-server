// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! OIDC ID token (JWS compact) verification, ТР-7.
//!
//! * Signature through the IdP's JWKS with `ring`; algorithms RS256, PS256
//!   and ES256 only — `none`, HMAC and everything else are rejected before
//!   any key is looked at, and a key's own `alg` must match the header.
//! * Exact `iss`, `aud` containing the client id, `azp` (required when there
//!   are several audiences, must equal the client id when present), `exp`,
//!   `iat`, `nbf` and `nonce`, with [`CLOCK_SKEW_SECONDS`] of clock skew.
//!
//! Unknown `kid` is reported as [`JwtError::UnknownKey`] so the caller can
//! refetch the JWKS once (rate limited) and retry.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature;
use serde_json::{Map, Value};

/// Allowed clock skew between this server and the IdP.
pub const CLOCK_SKEW_SECONDS: i64 = 60;
/// Upper bound of an ID token we are willing to parse.
const MAX_TOKEN_LEN: usize = 16 * 1024;
/// Keys tried for a token without `kid`.
const MAX_KEYS_TRIED: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    #[error("no matching signing key")]
    UnknownKey,
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid claim: {0}")]
    Claim(&'static str),
}

impl JwtError {
    /// Stable reason string for logs and audit metadata.
    pub const fn reason(&self) -> &'static str {
        match self {
            JwtError::Malformed => "malformed",
            JwtError::UnsupportedAlgorithm => "unsupported_alg",
            JwtError::UnknownKey => "unknown_kid",
            JwtError::BadSignature => "bad_signature",
            JwtError::Claim(c) => c,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Ps256,
    Es256,
}

impl Alg {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "RS256" => Some(Alg::Rs256),
            "PS256" => Some(Alg::Ps256),
            "ES256" => Some(Alg::Es256),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Ps256 => "PS256",
            Alg::Es256 => "ES256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyMaterial {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed SEC1 point `04 || x || y`.
    P256 {
        point: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    kid: Option<String>,
    /// The key's declared `alg`, if any.
    alg: Option<String>,
    key: KeyMaterial,
}

impl Jwk {
    fn usable_for(&self, alg: Alg) -> bool {
        if self.alg.as_deref().is_some_and(|a| a != alg.as_str()) {
            return false;
        }
        matches!(
            (&self.key, alg),
            (KeyMaterial::Rsa { .. }, Alg::Rs256 | Alg::Ps256)
                | (KeyMaterial::P256 { .. }, Alg::Es256)
        )
    }

    fn verify(&self, alg: Alg, message: &[u8], sig: &[u8]) -> bool {
        match (&self.key, alg) {
            (KeyMaterial::Rsa { n, e }, Alg::Rs256) => signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig)
                .is_ok(),
            (KeyMaterial::Rsa { n, e }, Alg::Ps256) => signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PSS_2048_8192_SHA256, message, sig)
                .is_ok(),
            (KeyMaterial::P256 { point }, Alg::Es256) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, sig)
                    .is_ok()
            }
            _ => false,
        }
    }
}

/// The usable signing keys of a JWKS document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWKS; keys that are not usable signing keys (encryption keys,
    /// other curves, symmetric keys, malformed entries) are skipped.
    pub fn parse(json: &[u8]) -> Result<Self, JwtError> {
        let doc: Value = serde_json::from_slice(json).map_err(|_| JwtError::Malformed)?;
        let entries = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(JwtError::Malformed)?;
        let mut keys = Vec::new();
        for k in entries {
            let s = |name: &str| k.get(name).and_then(Value::as_str);
            if s("use").is_some_and(|u| u != "sig") {
                continue;
            }
            let b = |name: &str| s(name).and_then(|v| URL_SAFE_NO_PAD.decode(v).ok());
            let key = match s("kty") {
                Some("RSA") => match (b("n"), b("e")) {
                    (Some(n), Some(e)) if n.len() >= 256 && !e.is_empty() => {
                        KeyMaterial::Rsa { n, e }
                    }
                    _ => continue,
                },
                Some("EC") if s("crv") == Some("P-256") => match (b("x"), b("y")) {
                    (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                        let mut point = Vec::with_capacity(65);
                        point.push(4);
                        point.extend_from_slice(&x);
                        point.extend_from_slice(&y);
                        KeyMaterial::P256 { point }
                    }
                    _ => continue,
                },
                _ => continue,
            };
            keys.push(Jwk {
                kid: s("kid").map(str::to_owned),
                alg: s("alg").map(str::to_owned),
                key,
            });
        }
        Ok(Self { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn has_kid(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid.as_deref() == Some(kid))
    }
}

/// What the ID token must match.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// The nonce of the authorization request; `None` for tokens from a
    /// refresh grant (OIDC Core 12.2: no nonce there).
    pub nonce: Option<&'a str>,
    /// Unix seconds.
    pub now: i64,
}

#[derive(Debug)]
struct Parsed<'a> {
    alg: Alg,
    kid: Option<String>,
    signing_input: &'a str,
    signature: Vec<u8>,
    claims: Map<String, Value>,
}

fn parse(token: &str) -> Result<Parsed<'_>, JwtError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(JwtError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    let header: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(h)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwtError::Malformed)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(Alg::parse)
        .ok_or(JwtError::UnsupportedAlgorithm)?;
    // Extensions we do not understand must not be ignored (RFC 7515 4.1.11).
    if header.contains_key("crit") {
        return Err(JwtError::Malformed);
    }
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.clone()),
        Some(_) => return Err(JwtError::Malformed),
    };
    let claims: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(JwtError::Malformed)?;
    let signature = URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::Malformed)?;
    Ok(Parsed {
        alg,
        kid,
        signing_input: &token[..h.len() + 1 + p.len()],
        signature,
        claims,
    })
}

/// The `kid` of a token's header (for the JWKS refetch decision).
pub fn header_kid(token: &str) -> Option<String> {
    parse(token).ok().and_then(|p| p.kid)
}

fn num(claims: &Map<String, Value>, name: &'static str) -> Result<Option<i64>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
            .map(Some)
            .ok_or(JwtError::Claim(name)),
    }
}

/// Verify signature and claims; returns the claims.
pub fn verify(
    token: &str,
    keys: &JwkSet,
    expect: &Expectations<'_>,
) -> Result<Map<String, Value>, JwtError> {
    let parsed = parse(token)?;
    let candidates: Vec<&Jwk> = keys
        .keys
        .iter()
        .filter(|k| k.usable_for(parsed.alg))
        .filter(|k| match &parsed.kid {
            Some(kid) => k.kid.as_deref() == Some(kid.as_str()),
            None => true,
        })
        .take(MAX_KEYS_TRIED)
        .collect();
    if candidates.is_empty() {
        return Err(JwtError::UnknownKey);
    }
    let message = parsed.signing_input.as_bytes();
    if !candidates
        .iter()
        .any(|k| k.verify(parsed.alg, message, &parsed.signature))
    {
        return Err(JwtError::BadSignature);
    }
    check_claims(&parsed.claims, expect)?;
    Ok(parsed.claims)
}

fn check_claims(c: &Map<String, Value>, expect: &Expectations<'_>) -> Result<(), JwtError> {
    let skew = CLOCK_SKEW_SECONDS;
    if c.get("iss").and_then(Value::as_str) != Some(expect.issuer) {
        return Err(JwtError::Claim("iss"));
    }
    match c.get("sub").and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s.len() <= 1024 => {}
        _ => return Err(JwtError::Claim("sub")),
    }
    let audiences: Vec<&str> = match c.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => return Err(JwtError::Claim("aud")),
    };
    if !audiences.contains(&expect.client_id) {
        return Err(JwtError::Claim("aud"));
    }
    match c.get("azp") {
        Some(Value::String(azp)) if azp == expect.client_id => {}
        Some(_) => return Err(JwtError::Claim("azp")),
        None if audiences.len() > 1 => return Err(JwtError::Claim("azp")),
        None => {}
    }
    let exp = num(c, "exp")?.ok_or(JwtError::Claim("exp"))?;
    if expect.now > exp.saturating_add(skew) {
        return Err(JwtError::Claim("exp"));
    }
    let iat = num(c, "iat")?.ok_or(JwtError::Claim("iat"))?;
    if iat > expect.now.saturating_add(skew) {
        return Err(JwtError::Claim("iat"));
    }
    if let Some(nbf) = num(c, "nbf")? {
        if nbf > expect.now.saturating_add(skew) {
            return Err(JwtError::Claim("nbf"));
        }
    }
    if let Some(nonce) = expect.nonce {
        let got = c.get("nonce").and_then(Value::as_str).unwrap_or("");
        if !crate::crypto::ct_eq(got.as_bytes(), nonce.as_bytes()) {
            return Err(JwtError::Claim("nonce"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::json;

    pub(crate) struct TestKey {
        pub kid: String,
        pair: EcdsaKeyPair,
    }

    impl TestKey {
        pub(crate) fn new(kid: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self {
                kid: kid.to_owned(),
                pair,
            }
        }

        pub(crate) fn jwk(&self) -> Value {
            let p = self.pair.public_key().as_ref();
            json!({
                "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": self.kid,
                "x": URL_SAFE_NO_PAD.encode(&p[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&p[33..65]),
            })
        }

        pub(crate) fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let sig = self
                .pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .unwrap();
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }

        pub(crate) fn token(&self, claims: &Value) -> String {
            self.sign(
                &json!({"alg": "ES256", "typ": "JWT", "kid": self.kid}),
                claims,
            )
        }
    }

    const ISS: &str = "https://idp.acme.test";
    const CLIENT: &str = "consolecrypt";
    const NOW: i64 = 1_800_000_000;

    fn claims() -> Value {
        json!({
            "iss": ISS, "aud": CLIENT, "sub": "user-1", "nonce": "n-1",
            "iat": NOW - 5, "exp": NOW + 300, "email": "a@acme.test"
        })
    }

    fn expect() -> Expectations<'static> {
        Expectations {
            issuer: ISS,
            client_id: CLIENT,
            nonce: Some("n-1"),
            now: NOW,
        }
    }

    fn set(keys: &[&TestKey]) -> JwkSet {
        let doc = json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() });
        JwkSet::parse(doc.to_string().as_bytes()).unwrap()
    }

    fn with(mut c: Value, k: &str, v: Value) -> Value {
        c[k] = v;
        c
    }

    #[test]
    fn valid_token() {
        let key = TestKey::new("k1");
        let verified = verify(&key.token(&claims()), &set(&[&key]), &expect()).unwrap();
        assert_eq!(verified["sub"], "user-1");
        // No kid in the header: every usable key is tried.
        let t = key.sign(&json!({"alg": "ES256"}), &claims());
        assert!(verify(&t, &set(&[&TestKey::new("other"), &key]), &expect()).is_ok());
        // Skew tolerance.
        let c = with(claims(), "exp", json!(NOW - 59));
        assert!(verify(&key.token(&c), &set(&[&key]), &expect()).is_ok());
    }

    #[test]
    fn rejects_foreign_issuer_audience_and_azp() {
        let key = TestKey::new("k1");
        let keys = set(&[&key]);
        let check = |c: Value| verify(&key.token(&c), &keys, &expect()).unwrap_err();
        assert_eq!(
            check(with(claims(), "iss", json!("https://evil.test"))),
            JwtError::Claim("iss")
        );
        assert_eq!(
            check(with(claims(), "iss", json!(format!("{ISS}/")))),
            JwtError::Claim("iss")
        );
        assert_eq!(
            check(with(claims(), "aud", json!("other"))),
            JwtError::Claim("aud")
        );
        assert_eq!(
            check(with(claims(), "aud", json!(["other"]))),
            JwtError::Claim("aud")
        );
        // Several audiences need azp = us.
        assert_eq!(
            check(with(claims(), "aud", json!([CLIENT, "other"]))),
            JwtError::Claim("azp")
        );
        assert_eq!(
            check(with(claims(), "azp", json!("other"))),
            JwtError::Claim("azp")
        );
        let ok = with(
            with(claims(), "aud", json!([CLIENT, "other"])),
            "azp",
            json!(CLIENT),
        );
        assert!(verify(&key.token(&ok), &keys, &expect()).is_ok());
        let mut no_sub = claims();
        no_sub.as_object_mut().unwrap().remove("sub");
        assert_eq!(check(no_sub), JwtError::Claim("sub"));
    }

    #[test]
    fn rejects_bad_nonce_and_times() {
        let key = TestKey::new("k1");
        let keys = set(&[&key]);
        let check = |c: Value| verify(&key.token(&c), &keys, &expect()).unwrap_err();
        assert_eq!(
            check(with(claims(), "nonce", json!("n-2"))),
            JwtError::Claim("nonce")
        );
        let mut no_nonce = claims();
        no_nonce.as_object_mut().unwrap().remove("nonce");
        assert_eq!(check(no_nonce.clone()), JwtError::Claim("nonce"));
        // A refresh-grant token has no nonce.
        let refresh = Expectations {
            nonce: None,
            ..expect()
        };
        assert!(verify(&key.token(&no_nonce), &keys, &refresh).is_ok());
        assert_eq!(
            check(with(claims(), "exp", json!(NOW - 61))),
            JwtError::Claim("exp")
        );
        assert_eq!(
            check(with(claims(), "exp", json!("soon"))),
            JwtError::Claim("exp")
        );
        assert_eq!(
            check(with(claims(), "iat", json!(NOW + 61))),
            JwtError::Claim("iat")
        );
        let mut no_iat = claims();
        no_iat.as_object_mut().unwrap().remove("iat");
        assert_eq!(check(no_iat), JwtError::Claim("iat"));
        assert_eq!(
            check(with(claims(), "nbf", json!(NOW + 120))),
            JwtError::Claim("nbf")
        );
    }

    #[test]
    fn rejects_none_hmac_and_unknown_algorithms() {
        let key = TestKey::new("k1");
        let keys = set(&[&key]);
        let body = URL_SAFE_NO_PAD.encode(claims().to_string());
        for alg in ["none", "None", "HS256", "HS512", "RS384", "ES384", "EdDSA"] {
            let header = URL_SAFE_NO_PAD.encode(json!({"alg": alg, "kid": "k1"}).to_string());
            // Classic confusion: HMAC "signed" with the public key as secret.
            let sig = ring::hmac::sign(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.jwk().to_string().as_bytes()),
                format!("{header}.{body}").as_bytes(),
            );
            for t in [
                format!("{header}.{body}."),
                format!("{header}.{body}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())),
            ] {
                assert_eq!(
                    verify(&t, &keys, &expect()).unwrap_err(),
                    JwtError::UnsupportedAlgorithm,
                    "{alg}"
                );
            }
        }
        // RS256 header with only an EC key → no usable key.
        let t = key.sign(&json!({"alg": "RS256", "kid": "k1"}), &claims());
        assert_eq!(
            verify(&t, &keys, &expect()).unwrap_err(),
            JwtError::UnknownKey
        );
        // crit extensions are refused.
        let t = key.sign(
            &json!({"alg": "ES256", "kid": "k1", "crit": ["x"], "x": 1}),
            &claims(),
        );
        assert_eq!(
            verify(&t, &keys, &expect()).unwrap_err(),
            JwtError::Malformed
        );
    }

    #[test]
    fn rejects_unknown_kid_and_bad_signatures() {
        let key = TestKey::new("k1");
        let other = TestKey::new("k1");
        let keys = set(&[&key]);
        let unknown = TestKey::new("k2").token(&claims());
        assert_eq!(
            verify(&unknown, &keys, &expect()).unwrap_err(),
            JwtError::UnknownKey
        );
        assert_eq!(header_kid(&unknown).as_deref(), Some("k2"));
        // Same kid, different key.
        assert_eq!(
            verify(&other.token(&claims()), &keys, &expect()).unwrap_err(),
            JwtError::BadSignature
        );
        // Tampered payload.
        let t = key.token(&claims());
        let mut parts: Vec<&str> = t.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(with(claims(), "sub", json!("admin")).to_string());
        parts[1] = &forged;
        assert_eq!(
            verify(&parts.join("."), &keys, &expect()).unwrap_err(),
            JwtError::BadSignature
        );
        for bad in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(verify(bad, &keys, &expect()).is_err());
        }
        assert_eq!(
            verify(&"a".repeat(MAX_TOKEN_LEN + 1), &keys, &expect()).unwrap_err(),
            JwtError::Malformed
        );
    }

    #[test]
    fn jwks_skips_unusable_keys_and_key_alg_must_match() {
        let key = TestKey::new("k1");
        let mut jwk = key.jwk();
        jwk["alg"] = json!("ES384");
        let doc = json!({"keys": [
            jwk,
            {"kty": "oct", "k": "c2VjcmV0", "kid": "h"},
            {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA", "kid": "p384"},
            {"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "short"},
            {"kty": "RSA", "use": "enc", "n": URL_SAFE_NO_PAD.encode([1u8; 256]), "e": "AQAB"},
        ]});
        let keys = JwkSet::parse(doc.to_string().as_bytes()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            verify(&key.token(&claims()), &keys, &expect()).unwrap_err(),
            JwtError::UnknownKey
        );
        assert!(JwkSet::parse(b"{}").is_err());
    }
}
