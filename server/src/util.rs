// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Small helpers shared by handlers: protocol enum ↔ DB text, input validation.

use crate::error::{AppError, AppResult};
use cc_protocol::auth::SecretString;
use cc_protocol::limits;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Serialize a unit-variant protocol enum to its wire string
/// (`RecipientType::Device` → `"device"`). Used for DB text columns so the DB
/// and the wire always agree.
pub fn enum_str<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => unreachable!("protocol enums serialize as strings"),
    }
}

/// Parse a wire string stored in the DB back into a protocol enum.
pub fn parse_enum<T: DeserializeOwned>(s: &str) -> AppResult<T> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| AppError::internal("unexpected enum value in database"))
}

/// Trimmed email with a minimal shape check. Stored as given (trimmed);
/// uniqueness is case-insensitive (`lower(email)` index).
pub fn normalize_email(email: &str) -> AppResult<String> {
    let e = email.trim();
    // A bare `local@domain` only: no display names, angle brackets, quotes,
    // comments or lists (mail libraries would otherwise deliver to a
    // different address than the one stored).
    let forbidden = |c: char| c.is_whitespace() || c.is_control() || "<>\"(),;:[]\\".contains(c);
    let valid = e.len() <= 254
        && !e.chars().any(forbidden)
        && matches!(e.split_once('@'), Some((local, domain))
            if !local.is_empty() && local.len() <= 64 && domain.contains('.')
               && !domain.starts_with('.') && !domain.ends_with('.') && !domain.contains('@'))
        && e.parse::<lettre::Address>().is_ok();
    if valid {
        Ok(e.to_owned())
    } else {
        Err(AppError::bad_request("invalid email address"))
    }
}

/// Rate-limit / lookup key for an email.
pub fn email_key(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn validate_account_password(pw: &SecretString) -> AppResult<()> {
    let len = pw.expose_secret().len();
    if len < limits::MIN_ACCOUNT_PASSWORD_LEN {
        return Err(AppError::bad_request(
            "password too short (minimum 12 bytes)",
        ));
    }
    if len > limits::MAX_ACCOUNT_PASSWORD_LEN {
        return Err(AppError::bad_request("password too long"));
    }
    Ok(())
}

/// Device display names: 1..=MAX_DEVICE_NAME_LEN characters, no control chars.
pub fn validate_device_name(name: &str) -> AppResult<String> {
    let n = name.trim();
    if n.is_empty()
        || n.chars().count() > limits::MAX_DEVICE_NAME_LEN
        || n.chars().any(char::is_control)
    {
        return Err(AppError::bad_request("invalid device name"));
    }
    Ok(n.to_owned())
}

/// Optional free-text fields that end up in the DB (client version, revoke
/// reason): bounded and control-character free.
pub fn short_text(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.map(|v| v.trim()).filter(|v| !v.is_empty()).map(|v| {
        v.chars()
            .filter(|c| !c.is_control())
            .take(max_chars)
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_protocol::envelopes::RecipientType;

    #[test]
    fn enum_roundtrip() {
        assert_eq!(enum_str(&RecipientType::Device), "device");
        let r: RecipientType = parse_enum("recovery").unwrap();
        assert_eq!(r, RecipientType::Recovery);
        assert!(parse_enum::<RecipientType>("nope").is_err());
    }

    #[test]
    fn emails() {
        assert_eq!(
            normalize_email("  Alice@Example.org ").unwrap(),
            "Alice@Example.org"
        );
        for bad in [
            "",
            "a",
            "a@b",
            "@b.c",
            "a b@c.d",
            "a@.c",
            "a@c.",
            "a@b@c.d",
            "victim<attacker@evil.example>",
            "<victim@corp.example>",
            "\"q\"@x.example",
            "a@x.example,b@y.example",
            "a(comment)@x.example",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad}");
        }
        assert_eq!(email_key(" A@B.C "), "a@b.c");
    }

    #[test]
    fn device_names() {
        assert_eq!(validate_device_name(" Work Mac ").unwrap(), "Work Mac");
        assert!(validate_device_name("   ").is_err());
        assert!(validate_device_name("bad\nname").is_err());
        assert!(validate_device_name(&"x".repeat(129)).is_err());
    }

    #[test]
    fn short_text_is_bounded() {
        assert_eq!(short_text(Some(" 1.2.3 "), 64).as_deref(), Some("1.2.3"));
        assert_eq!(short_text(Some("a\u{7}b"), 64).as_deref(), Some("ab"));
        assert_eq!(short_text(Some("abcdef"), 3).as_deref(), Some("abc"));
        assert_eq!(short_text(Some("  "), 3), None);
    }
}
