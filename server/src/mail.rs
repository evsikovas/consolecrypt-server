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
use lettre::message::Mailbox;
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
}

impl MailKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            MailKind::VerifyEmail => "verify_email",
            MailKind::PasswordReset => "password_reset",
            MailKind::AccountRecovery => "account_recovery",
            MailKind::DeviceRevoked => "device_revoked",
            MailKind::PasswordChanged => "password_changed",
        }
    }
}

pub struct MailMessage {
    pub kind: MailKind,
    pub to: String,
    pub subject: String,
    /// May contain a token. Never log.
    pub body: String,
}

impl fmt::Debug for MailMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailMessage")
            .field("kind", &self.kind)
            .field("body", &"<redacted>")
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
            // Transport errors can quote the recipient address (PII): the
            // details go to debug only.
            tracing::warn!(kind = kind.as_str(), "failed to send mail");
            tracing::debug!(kind = kind.as_str(), error = %err, "mail failure details");
        }
    });
}

fn build_message(from: &Mailbox, msg: &MailMessage) -> anyhow::Result<Message> {
    let to: Mailbox = msg
        .to
        .parse()
        .map_err(|_| anyhow::anyhow!("recipient is not a valid mailbox"))?;
    Ok(Message::builder()
        .from(from.clone())
        .to(to)
        .subject(msg.subject.clone())
        .body(msg.body.clone())?)
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

/// Message templates. Plain text; tokens are pasted into the client app.
pub mod templates {
    use super::{MailKind, MailMessage};

    fn footer(public_url: Option<&str>) -> String {
        match public_url {
            Some(url) => format!("\n\n-- \nConsoleCrypt server at {url}\n"),
            None => "\n\n-- \nConsoleCrypt\n".to_owned(),
        }
    }

    pub fn verify_email(to: &str, token: &str, public_url: Option<&str>) -> MailMessage {
        MailMessage {
            kind: MailKind::VerifyEmail,
            to: to.to_owned(),
            subject: "Verify your ConsoleCrypt email address".to_owned(),
            body: format!(
                "Paste this verification code into the ConsoleCrypt app:\n\n    {token}\n\n\
                 If you did not create an account, ignore this message.{}",
                footer(public_url)
            ),
        }
    }

    pub fn password_reset(
        to: &str,
        token: &str,
        recovery: bool,
        public_url: Option<&str>,
    ) -> MailMessage {
        MailMessage {
            kind: if recovery {
                MailKind::AccountRecovery
            } else {
                MailKind::PasswordReset
            },
            to: to.to_owned(),
            subject: "Reset your ConsoleCrypt account password".to_owned(),
            body: format!(
                "Paste this code into the ConsoleCrypt app to set a new account password:\n\n    {token}\n\n\
                 It expires soon and can be used once. Resetting the account password signs out \
                 all devices but does not unlock your vault: you still need your vault passphrase, \
                 your Recovery Key or a trusted device.\n\n\
                 If you did not request this, ignore this message.{}",
                footer(public_url)
            ),
        }
    }

    pub fn device_revoked(to: &str, device_name: &str, public_url: Option<&str>) -> MailMessage {
        MailMessage {
            kind: MailKind::DeviceRevoked,
            to: to.to_owned(),
            subject: "A device was removed from your ConsoleCrypt account".to_owned(),
            body: format!(
                "The device \"{device_name}\" was revoked and can no longer sync.\n\n\
                 If this was not you, sign in on a trusted device, review your devices and \
                 change your account password.{}",
                footer(public_url)
            ),
        }
    }

    pub fn password_changed(to: &str, public_url: Option<&str>) -> MailMessage {
        MailMessage {
            kind: MailKind::PasswordChanged,
            to: to.to_owned(),
            subject: "Your ConsoleCrypt account password was changed".to_owned(),
            body: format!(
                "Your account password was changed and other sessions were signed out.\n\n\
                 If this was not you, reset your password immediately.{}",
                footer(public_url)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_body() {
        let m = templates::verify_email("a@example.org", "cct_SECRET", None);
        assert!(!format!("{m:?}").contains("SECRET"));
    }

    #[tokio::test]
    async fn file_mailer_writes_private_file() {
        let dir = std::env::temp_dir().join(format!("cc-mail-test-{}", uuid::Uuid::now_v7()));
        let mailer = FileMailer {
            dir: dir.clone(),
            from: "ConsoleCrypt <no-reply@localhost>".parse().unwrap(),
        };
        mailer
            .send(templates::verify_email("a@example.org", "cct_TOKEN", None))
            .await
            .unwrap();
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let path = entries[0].as_ref().unwrap().path();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("cct_TOKEN"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
