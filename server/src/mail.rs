// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Outgoing mail (verification, password reset, security notices).
//!
//! Message bodies may contain single-use tokens, so bodies are never logged;
//! only the message kind is. Transports:
//!
//! * `smtp` — lettre over STARTTLS / implicit TLS (or plain for a local relay);
//! * `file` — development: each message is written to a file in a local,
//!   git-ignored directory (mode 0600 on Unix); nothing goes to the logs;
//! * `disabled` — messages are dropped; self-hosters use the admin CLI
//!   (`consolecrypt-server admin reset-token …`).

use crate::config::{MailConfig, MailTransport, SmtpTls};
use futures_util::future::BoxFuture;
use lettre::message::header::{ContentTransferEncoding, ContentType};
use lettre::message::{Body, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailKind {
    VerifyEmail,
    PasswordReset,
    AccountRecovery,
    DeviceRevoked,
    PasswordChanged,
    NewDevice,
    EnvelopeAbuse,
    PasswordResetCompleted,
    TeamInvitation,
    FailedLogins,
}

impl MailKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            MailKind::VerifyEmail => "verify_email",
            MailKind::PasswordReset => "password_reset",
            MailKind::AccountRecovery => "account_recovery",
            MailKind::DeviceRevoked => "device_revoked",
            MailKind::PasswordChanged => "password_changed",
            MailKind::NewDevice => "new_device",
            MailKind::EnvelopeAbuse => "envelope_abuse",
            MailKind::PasswordResetCompleted => "password_reset_completed",
            MailKind::TeamInvitation => "team_invitation",
            MailKind::FailedLogins => "failed_logins",
        }
    }
}

pub struct MailMessage {
    pub kind: MailKind,
    pub to: String,
    pub subject: String,
    /// Plain-text part. May contain a token. Never log.
    pub body: String,
    /// HTML part (multipart/alternative). May contain a token. Never log.
    pub html: Option<String>,
}

impl fmt::Debug for MailMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailMessage")
            .field("kind", &self.kind)
            .field("body", &"<redacted>")
            .field("html", &self.html.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

pub trait Mailer: Send + Sync + fmt::Debug {
    fn send(&self, msg: MailMessage) -> BoxFuture<'_, anyhow::Result<()>>;
    /// Whether messages actually reach users (affects UX hints only).
    fn delivers(&self) -> bool;
}

/// Build the configured mailer.
pub fn from_config(cfg: &MailConfig) -> anyhow::Result<Arc<dyn Mailer>> {
    let from: Mailbox = cfg
        .from
        .parse()
        .map_err(|_| anyhow::anyhow!("CC_MAIL_FROM is not a valid mailbox"))?;
    Ok(match &cfg.transport {
        MailTransport::Disabled => Arc::new(DisabledMailer),
        MailTransport::File { dir } => Arc::new(FileMailer {
            dir: dir.clone(),
            from,
        }),
        MailTransport::Smtp {
            host,
            port,
            username,
            password,
            tls,
        } => {
            let builder = match tls {
                SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
                SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
                SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
            };
            let mut builder = builder.port(*port);
            if let (Some(u), Some(p)) = (username, password) {
                builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
            }
            Arc::new(SmtpMailer {
                transport: builder.build(),
                from,
            })
        }
    })
}

/// Send in the background: callers never wait on SMTP, and failures are
/// logged without content.
pub fn send_in_background(mailer: Arc<dyn Mailer>, msg: MailMessage) {
    let kind = msg.kind;
    tokio::spawn(async move {
        if let Err(err) = mailer.send(msg).await {
            // SMTP responses are remote input and may echo credentials or
            // recipient data. Log only a bounded local category at every level.
            tracing::warn!(
                kind = kind.as_str(),
                failure = mail_failure_kind(&err),
                "failed to send mail"
            );
        }
    });
}

fn mail_failure_kind(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<lettre::transport::smtp::Error>() {
        Some(error) if error.is_timeout() => "timeout",
        Some(error) if error.is_tls() => "tls",
        Some(error) if error.is_transient() => "smtp_transient",
        Some(error) if error.is_permanent() => "smtp_permanent",
        Some(_) => "smtp_transport",
        None => "mail_internal",
    }
}

fn build_message(from: &Mailbox, msg: &MailMessage) -> anyhow::Result<Message> {
    let to: Mailbox = msg
        .to
        .parse()
        .map_err(|_| anyhow::anyhow!("recipient is not a valid mailbox"))?;
    let builder = Message::builder()
        .from(from.clone())
        .to(to)
        .subject(msg.subject.clone());
    // Every part declares charset=utf-8 (mail clients must not guess a legacy
    // charset for Cyrillic) and is base64-encoded (no long-line limits for the
    // HTML part, deterministic on the wire).
    let part = |content_type: ContentType, text: &str| {
        SinglePart::builder().header(content_type).body(
            Body::new_with_encoding(text.to_owned(), ContentTransferEncoding::Base64)
                .expect("base64 can encode any body"),
        )
    };
    Ok(match &msg.html {
        Some(html) => builder.multipart(
            MultiPart::alternative()
                .singlepart(part(ContentType::TEXT_PLAIN, &msg.body))
                .singlepart(part(ContentType::TEXT_HTML, html)),
        )?,
        None => builder.singlepart(part(ContentType::TEXT_PLAIN, &msg.body))?,
    })
}

#[derive(Debug)]
pub struct DisabledMailer;

impl Mailer for DisabledMailer {
    fn send(&self, msg: MailMessage) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            tracing::info!(
                kind = msg.kind.as_str(),
                "mail transport disabled; message dropped (use the admin CLI)"
            );
            Ok(())
        })
    }

    fn delivers(&self) -> bool {
        false
    }
}

pub struct FileMailer {
    dir: PathBuf,
    from: Mailbox,
}

impl fmt::Debug for FileMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileMailer")
            .field("dir", &self.dir)
            .finish()
    }
}

impl Mailer for FileMailer {
    fn send(&self, msg: MailMessage) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let message = build_message(&self.from, &msg)?;
            let name = format!(
                "{}-{}-{}.eml",
                chrono::Utc::now().format("%Y%m%dT%H%M%S"),
                msg.kind.as_str(),
                uuid::Uuid::now_v7().simple()
            );
            let path = self.dir.join(&name);
            let bytes = message.formatted();
            let dir = self.dir.clone();
            tokio::task::spawn_blocking(move || write_private(&dir, &path, &bytes)).await??;
            tracing::info!(kind = msg.kind.as_str(), file = %name, "dev mail written");
            Ok(())
        })
    }

    fn delivers(&self) -> bool {
        true
    }
}

fn write_private(
    dir: &std::path::Path,
    path: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::create_dir_all(dir)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SmtpMailer")
    }
}

impl Mailer for SmtpMailer {
    fn send(&self, msg: MailMessage) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let message = build_message(&self.from, &msg)?;
            self.transport.send(message).await?;
            tracing::info!(kind = msg.kind.as_str(), "mail sent");
            Ok(())
        })
    }

    fn delivers(&self) -> bool {
        true
    }
}

pub mod templates;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MailLanguage;
    use std::time::Duration;

    fn ctx(url: Option<&str>) -> templates::Ctx<'_> {
        templates::Ctx {
            public_url: url,
            language: MailLanguage::Ru,
        }
    }

    const TTL: Duration = Duration::from_secs(3600);

    /// Decoded bodies of the `content_type` parts of a formatted message.
    fn parts(wire: &str, content_type: &str) -> Vec<String> {
        use base64::Engine as _;
        let mut out = Vec::new();
        let header = format!("Content-Type: {content_type}\r\n");
        let mut rest = wire;
        while let Some(i) = rest.find(&header) {
            rest = &rest[i + header.len()..];
            let (headers, after) = rest.split_once("\r\n\r\n").unwrap();
            assert!(
                headers.contains("Content-Transfer-Encoding: base64"),
                "{content_type} part must be base64"
            );
            let end = after.find("\r\n--").unwrap_or(after.len());
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(after[..end].split_whitespace().collect::<String>())
                .unwrap();
            out.push(String::from_utf8(decoded).unwrap());
            rest = &after[end..];
        }
        out
    }

    #[test]
    fn all_templates_are_utf8_multipart_alternative_on_the_wire() {
        let from = "ConsoleCrypt <no-reply@example.org>".parse().unwrap();
        let token = format!("cct_{}", uuid::Uuid::new_v4().simple());
        for url in [None, Some("https://example.org")] {
            let c = ctx(url);
            let messages = [
                templates::verify_email(c, "a@example.org", &token, TTL),
                templates::password_reset(c, "a@example.org", &token, false, TTL),
                templates::password_reset(c, "a@example.org", &token, true, TTL),
                templates::failed_logins(c, "a@example.org"),
                templates::device_revoked(c, "a@example.org", "Мой ноутбук"),
                templates::password_changed(c, "a@example.org"),
                templates::new_device(
                    c,
                    "a@example.org",
                    &templates::NewDeviceInfo {
                        name: "Ноутбук",
                        platform: "linux",
                        client_version: Some("0.8.6"),
                        at: chrono::Utc::now(),
                        ip: Some("192.0.2.1".parse().unwrap()),
                    },
                    "ccd_x",
                ),
                templates::new_device_summary(c, "a@example.org"),
                templates::envelope_abuse(c, "a@example.org", "Ноутбук", "ccd_x"),
                templates::password_changed_new_device(c, "a@example.org", "Ноутбук", "ccd_x"),
                templates::password_reset_completed(
                    c,
                    "a@example.org",
                    &["Ноутбук".into()],
                    "ccd_x",
                ),
                templates::team_invitation(
                    c,
                    "a@example.org",
                    "boss@example.org",
                    "editor",
                    Some("Ops"),
                ),
            ];
            for msg in messages {
                let wire =
                    String::from_utf8(build_message(&from, &msg).unwrap().formatted()).unwrap();
                let (headers, _) = wire.split_once("\r\n\r\n").unwrap();
                // Decoding bytes as UTF-8 in a test is insufficient: email clients
                // need both MIME and an explicit charset to choose that decoder.
                assert!(headers.lines().any(|line| line == "MIME-Version: 1.0"));
                assert!(headers.contains("Content-Type: multipart/alternative"));
                assert_eq!(
                    parts(&wire, "text/plain; charset=utf-8"),
                    vec![msg.body.replace('\n', "\r\n")]
                );
                let html = parts(&wire, "text/html; charset=utf-8");
                assert_eq!(html.len(), 1);
                assert!(html[0].starts_with("<!DOCTYPE html>"));
            }
        }
    }

    #[test]
    fn debug_redacts_body_and_html() {
        let m = templates::verify_email(ctx(None), "a@example.org", "cct_SECRET", TTL);
        assert!(!format!("{m:?}").contains("SECRET"));
    }

    #[tokio::test]
    async fn file_mailer_writes_private_file() {
        let dir = std::env::temp_dir().join(format!("cc-mail-test-{}", uuid::Uuid::now_v7()));
        let mailer = FileMailer {
            dir: dir.clone(),
            from: "ConsoleCrypt <no-reply@localhost>".parse().unwrap(),
        };
        let token = format!("cct_{}", uuid::Uuid::new_v4().simple());
        let msg = templates::verify_email(ctx(None), "a@example.org", &token, TTL);
        let expected_body = msg.body.replace('\n', "\r\n");
        mailer.send(msg).await.unwrap();
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let path = entries[0].as_ref().unwrap().path();
        let content = std::fs::read_to_string(&path).unwrap();
        // UTF-8 templates are MIME/base64 encoded. Check the decoded wire
        // parts, not whether an ASCII token survived encoding.
        assert_eq!(
            parts(&content, "text/plain; charset=utf-8"),
            vec![expected_body]
        );
        assert!(parts(&content, "text/html; charset=utf-8")[0].contains(&token));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
