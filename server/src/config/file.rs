// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit, data-only native configuration. Never load files from the cwd,
//! interpolate shell expressions, mutate the environment or echo parse input.

use super::ConfigError;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

#[path = "keys.rs"]
mod keys;
const MAX_BYTES: u64 = 64 * 1024;

/// Process environment takes precedence, including explicit empty values.
pub struct ConfigSource {
    environment: HashMap<String, String>,
    file: HashMap<String, String>,
}

impl fmt::Debug for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigSource(<redacted>)")
    }
}

impl ConfigSource {
    /// `--config` wins over `CC_CONFIG_FILE`. An explicit missing/unsafe file
    /// is an error; it must never silently fall back to deployment defaults.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        // Other environment variables may contain unrelated credentials.
        let environment = std::env::vars()
            .filter(|(key, _)| keys::KEYS.contains(&key.as_str()) || key == "CC_CONFIG_FILE")
            .collect::<HashMap<_, _>>();
        let path = path.or_else(|| {
            environment
                .get("CC_CONFIG_FILE")
                .filter(|value| !value.trim().is_empty())
                .map(Path::new)
        });
        let file = match path {
            Some(path) => read_file(path)?,
            None => HashMap::new(),
        };
        Ok(Self { environment, file })
    }

    pub fn get(&self, key: &str) -> Option<String> {
        // The legacy DATABASE_URL alias must not lose to CC_DATABASE_URL in
        // the file when an operator explicitly overrides it via environment.
        if key == "CC_DATABASE_URL" && !self.environment.contains_key(key) {
            if let Some(value) = self.environment.get("DATABASE_URL") {
                return Some(value.clone());
            }
        }
        self.environment
            .get(key)
            .or_else(|| self.file.get(key))
            .cloned()
    }
}

fn read_file(path: &Path) -> Result<HashMap<String, String>, ConfigError> {
    let error = || ConfigError("config file: cannot read a private regular file".into());
    // Check before opening too, so a named pipe cannot stall startup.
    if !std::fs::metadata(path).map_err(|_| error())?.is_file() {
        return Err(error());
    }
    let file = std::fs::File::open(path).map_err(|_| error())?;
    let metadata = file.metadata().map_err(|_| error())?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err(error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError(
                "config file: permissions must be 0600 or 0400".into(),
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error())?;
    if bytes.len() > MAX_BYTES as usize {
        return Err(error());
    }
    parse(&bytes)
}

fn parse(bytes: &[u8]) -> Result<HashMap<String, String>, ConfigError> {
    // serde_json diagnostics can contain the actual password, even for a
    // type error. Keep all parser errors independent of keys and values.
    serde_json::from_slice::<Settings>(bytes).map(|value| value.0).map_err(|_| {
        ConfigError("config file: expected one JSON object of supported, unique CC_* keys with string values".into())
    })
}

struct Settings(HashMap<String, String>);
impl<'de> Deserialize<'de> for Settings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SettingsVisitor;
        impl<'de> Visitor<'de> for SettingsVisitor {
            type Value = Settings;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a settings object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Settings, A::Error> {
                let mut settings = HashMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if !keys::KEYS.contains(&key.as_str()) || settings.insert(key, value).is_some()
                    {
                        return Err(serde::de::Error::custom(
                            "unknown or duplicate configuration key",
                        ));
                    }
                }
                Ok(Settings(settings))
            }
        }
        deserializer.deserialize_map(SettingsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn preserves_password_literals_and_environment_precedence() {
        let password = format!("{} ${{HOME}} # ' \\\" ", uuid::Uuid::new_v4());
        let file = parse(
            &serde_json::to_vec(&serde_json::json!({
                "CC_DATABASE_URL": "postgres://localhost/test",
                "CC_SMTP_PASSWORD": password,
                "CC_MAIL_TRANSPORT": "smtp", "CC_SMTP_HOST": "smtp.example.invalid",
                "CC_SMTP_PORT": "465", "CC_SMTP_TLS": "tls"
            }))
            .unwrap(),
        )
        .unwrap();
        let mut source = ConfigSource {
            environment: HashMap::new(),
            file,
        };
        assert!(source.get("CC_SMTP_PASSWORD").as_deref() == Some(&password));
        let config = Config::from_lookup(|key| source.get(key)).unwrap();
        assert!(!format!("{source:?} {config:?}").contains(&password));
        source
            .environment
            .insert("CC_SMTP_PASSWORD".into(), "".into());
        assert_eq!(source.get("CC_SMTP_PASSWORD").as_deref(), Some(""));
        source.environment.insert(
            "DATABASE_URL".into(),
            "postgres://localhost/override".into(),
        );
        assert_eq!(
            source.get("CC_DATABASE_URL").as_deref(),
            Some("postgres://localhost/override")
        );
        source.environment.insert(
            "CC_DATABASE_URL".into(),
            "postgres://localhost/primary".into(),
        );
        assert_eq!(
            source.get("CC_DATABASE_URL").as_deref(),
            Some("postgres://localhost/primary")
        );
    }

    #[test]
    fn rejects_typos_duplicates_and_wrong_types_without_echoing_input() {
        let secret = uuid::Uuid::new_v4().to_string();
        for input in [
            format!(r#"{{"{secret}":"value"}}"#),
            format!(r#"{{"CC_SMTP_PASSWORD":["{secret}"]}}"#),
            format!(r#"{{"CC_SMTP_PASSWORD":"{secret}","CC_SMTP_PASSWORD":"other"}}"#),
            format!(r#"{{"CC_SMTP_PASSWORD":"{secret}""#),
        ] {
            let error = parse(input.as_bytes()).unwrap_err();
            assert!(!format!("{error:?} {error}").contains(&secret));
        }
    }

    #[test]
    fn accepts_only_private_bounded_regular_files() {
        let path = std::env::temp_dir().join(format!("cc-config-{}", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(&path).unwrap();
        file.write_all(b"{\"CC_LISTEN_ADDR\":\"127.0.0.1:9080\"}")
            .unwrap();
        assert_eq!(
            read_file(&path).unwrap()["CC_LISTEN_ADDR"],
            "127.0.0.1:9080"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o644))
                .unwrap();
            assert!(read_file(&path).is_err());
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(read_file(&path).is_err());
        drop(file);
        std::fs::remove_file(&path).unwrap();
        assert!(read_file(&path).is_err());
        assert!(read_file(&std::env::temp_dir()).is_err());
    }
}
