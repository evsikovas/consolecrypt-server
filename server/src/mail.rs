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
use lettre::message::{Mailbox, SinglePart};
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
    Ok(Message::builder()
        .from(from.clone())
        .to(to)
        .subject(msg.subject.clone())
        // Declare MIME 1.0 and text/plain; charset=utf-8, so mail clients
        // decode Cyrillic instead of guessing a legacy charset.
        .singlepart(SinglePart::plain(msg.body.clone()))?)
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

/// Plain-text messages work in both the app and web account. Codes in web
/// links are fragments, so they do not enter HTTP access logs.
pub mod templates {
    use super::{MailKind, MailMessage};

    fn footer(public_url: Option<&str>) -> String {
        match public_url {
            Some(url) => format!("\n\n-- \nConsoleCrypt server at {url}\n"),
            None => "\n\n-- \nConsoleCrypt\n".to_owned(),
        }
    }

    fn account_link(public_url: Option<&str>, action: &str, token: &str) -> String {
        public_url
            .map(|url| {
                format!(
                    "\n\nОткрыть личный кабинет:\n{}/account#action={action}&token={token}",
                    url.trim_end_matches('/')
                )
            })
            .unwrap_or_default()
    }

    pub fn verify_email(to: &str, token: &str, public_url: Option<&str>) -> MailMessage {
        MailMessage {
            kind: MailKind::VerifyEmail,
            to: to.to_owned(),
            subject: "ConsoleCrypt — подтвердите email".to_owned(),
            body: format!(
                "Подтвердите email в ConsoleCrypt. Вставьте этот код в приложение или личный кабинет:\n\n    {token}\n\n\
                 Если вы не создавали аккаунт, просто проигнорируйте это письмо.{}{}",
                account_link(public_url, "verify", token),
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
            subject: "ConsoleCrypt — восстановление доступа".to_owned(),
            body: format!(
                "Для изменения пароля аккаунта ConsoleCrypt вставьте этот одноразовый код:\n\n    {token}\n\n\
                 Код действует ограниченное время. После смены пароля все сеансы будут завершены. \
                 Это не разблокирует хранилище: для него нужна парольная фраза, \
                 ключ восстановления или доверенное устройство.\n\n\
                 Если вы не запрашивали восстановление, проигнорируйте это письмо.{}{}",
                if recovery { String::new() } else { account_link(public_url, "reset", token) },
                footer(public_url)
            ),
        }
    }

    /// Many failed sign-ins to the account from many networks (security
    /// audit S2, TR-8); at most one a day.
    pub fn failed_logins(to: &str, public_url: Option<&str>) -> MailMessage {
        MailMessage {
            kind: MailKind::FailedLogins,
            to: to.to_owned(),
            subject: "ConsoleCrypt — много неудачных попыток входа / Many failed sign-in attempts"
                .to_owned(),
            body: format!(
                "Кто-то многократно пытается войти в ваш аккаунт ConsoleCrypt с неверным паролем. \
                 Сервер временно ограничил попытки входа с новых устройств. Ваши устройства, \
                 на которых вы уже входили, по-прежнему могут войти.\n\n\
                 Если это были не вы, задайте длинный уникальный пароль аккаунта и проверьте \
                 список устройств.\n\n\
                 Someone is repeatedly trying to sign in to your ConsoleCrypt account with a wrong \
                 password. The server has temporarily limited sign-ins from new devices; the \
                 devices you already use can still sign in.\n\n\
                 If this was not you, use a long unique account password and review your \
                 devices.{}",
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

    /// "This wasn't me" link of the device-protection mails (protocol 1.7).
    fn deny_link(public_url: Option<&str>, token: &str) -> String {
        match public_url {
            Some(url) => format!(
                "\n\nЭто не я — отозвать это устройство / This wasn't me — revoke this device:\n\
                 {}/account#action=deny-device&token={token}",
                url.trim_end_matches('/')
            ),
            None => "\n\nЕсли это не вы, отзовите устройство на доверенном устройстве и смените \
                     пароль аккаунта. / If this wasn't you, revoke the device on a trusted \
                     device and change your account password."
                .to_owned(),
        }
    }

    /// What the "new device" mail tells about the device.
    #[derive(Debug)]
    pub struct NewDeviceInfo<'a> {
        pub name: &'a str,
        pub platform: &'a str,
        pub client_version: Option<&'a str>,
        pub at: chrono::DateTime<chrono::Utc>,
        pub ip: Option<std::net::IpAddr>,
    }

    pub fn new_device(
        to: &str,
        info: &NewDeviceInfo<'_>,
        token: &str,
        public_url: Option<&str>,
    ) -> MailMessage {
        let at = info.at.format("%Y-%m-%d %H:%M UTC");
        let version = info.client_version.unwrap_or("—");
        let ip = info
            .ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "—".to_owned());
        MailMessage {
            kind: MailKind::NewDevice,
            to: to.to_owned(),
            subject: "ConsoleCrypt — вход с нового устройства / New device signed in".to_owned(),
            body: format!(
                "В ваш аккаунт ConsoleCrypt вошло новое устройство.\n\
                 A new device signed in to your ConsoleCrypt account.\n\n\
                 Устройство / Device: \"{name}\"\n\
                 Платформа / Platform: {platform}\n\
                 Версия / Version: {version}\n\
                 Время / Time: {at}\n\
                 IP: {ip}\n\n\
                 Если это вы — ничего делать не нужно. Первые дни новое устройство не может \
                 отзывать ваши доверенные устройства.\n\
                 If this was you, there is nothing to do. For its first days a new device \
                 cannot revoke your trusted devices.{}{}",
                deny_link(public_url, token),
                footer(public_url),
                name = info.name,
                platform = info.platform,
            ),
        }
    }

    /// Teams (protocol 1.9): an account was invited into a team. The team
    /// name is end-to-end encrypted, so only the inviter, the role and the
    /// inviter's plain-text note can be shown.
    pub fn team_invitation(
        to: &str,
        inviter: &str,
        role: &str,
        note: Option<&str>,
        public_url: Option<&str>,
    ) -> MailMessage {
        let note_ru = note
            .map(|n| format!("\n\nКомментарий приглашения: {n}"))
            .unwrap_or_default();
        let note_en = note
            .map(|n| format!("\n\nInvitation note: {n}"))
            .unwrap_or_default();
        MailMessage {
            kind: MailKind::TeamInvitation,
            to: to.to_owned(),
            subject: "ConsoleCrypt — приглашение в команду / Team invitation".to_owned(),
            body: format!(
                "{inviter} приглашает вас в команду ConsoleCrypt (роль: {role}).{note_ru}\n\n\
                 Откройте ConsoleCrypt → Настройки → Команды, примите приглашение и сверьте \
                 код с {inviter} — по телефону или лично. Доступ появится только после того, \
                 как коды совпадут. Если вы не ждали приглашения, просто отклоните его.\n\n\
                 {inviter} invited you to a ConsoleCrypt team (role: {role}).{note_en}\n\n\
                 Open ConsoleCrypt → Settings → Teams, accept the invitation and compare the \
                 code with {inviter} by phone or in person. Access is granted only after the \
                 codes match. If you did not expect this, decline it.{}",
                footer(public_url)
            ),
        }
    }

    /// Sent once when an hour has more sign-ins than individual mails.
    pub fn new_device_summary(to: &str, public_url: Option<&str>) -> MailMessage {
        MailMessage {
            kind: MailKind::NewDevice,
            to: to.to_owned(),
            subject: "ConsoleCrypt — много входов с новых устройств / Many new device sign-ins"
                .to_owned(),
            body: format!(
                "За последний час в ваш аккаунт ConsoleCrypt вошло много новых устройств. \
                 Отдельных писем о них в этот час больше не будет. Проверьте список устройств \
                 на доверенном устройстве и, если это не вы, смените пароль аккаунта.\n\n\
                 Many new devices signed in to your ConsoleCrypt account in the last hour. \
                 No further mails are sent for them this hour. Review your devices on a trusted \
                 device and, if this wasn't you, change your account password.{}",
                footer(public_url)
            ),
        }
    }

    pub fn envelope_abuse(
        to: &str,
        device_name: &str,
        token: &str,
        public_url: Option<&str>,
    ) -> MailMessage {
        MailMessage {
            kind: MailKind::EnvelopeAbuse,
            to: to.to_owned(),
            subject: "ConsoleCrypt — повторные попытки доступа к хранилищу / Repeated vault access attempts"
                .to_owned(),
            body: format!(
                "Кто-то многократно запрашивает доступ к хранилищу с устройства \"{device_name}\". \
                 Сервер временно ограничил такие запросы.\n\n\
                 Someone is repeatedly requesting access to your vault from the device \
                 \"{device_name}\". The server has temporarily limited these requests.{}{}",
                deny_link(public_url, token),
                footer(public_url)
            ),
        }
    }

    /// The account password was changed from a device in quarantine:
    /// trusted devices stay signed in (TR-7).
    pub fn password_changed_new_device(
        to: &str,
        device_name: &str,
        token: &str,
        public_url: Option<&str>,
    ) -> MailMessage {
        MailMessage {
            kind: MailKind::PasswordChanged,
            to: to.to_owned(),
            subject: "ConsoleCrypt — пароль изменён с нового устройства / Password changed from a new device"
                .to_owned(),
            body: format!(
                "Пароль аккаунта ConsoleCrypt изменён с нового устройства \"{device_name}\". \
                 Ваши доверенные устройства остались в аккаунте.\n\n\
                 Your ConsoleCrypt account password was changed from the new device \
                 \"{device_name}\". Your trusted devices stay signed in.{}\n\n\
                 После отзыва смените пароль через «Забыли пароль?». / After revoking, reset \
                 the password via \"Forgot password?\".{}",
                deny_link(public_url, token),
                footer(public_url)
            ),
        }
    }

    /// TR-13: after a password reset, with the devices it revoked.
    pub fn password_reset_completed(
        to: &str,
        revoked: &[String],
        token: &str,
        public_url: Option<&str>,
    ) -> MailMessage {
        let list = if revoked.is_empty() {
            "—".to_owned()
        } else {
            revoked
                .iter()
                .map(|n| format!("  • \"{n}\""))
                .collect::<Vec<_>>()
                .join("\n")
        };
        MailMessage {
            kind: MailKind::PasswordResetCompleted,
            to: to.to_owned(),
            subject: "ConsoleCrypt — пароль аккаунта сброшен / Account password was reset"
                .to_owned(),
            body: format!(
                "Пароль аккаунта ConsoleCrypt сброшен, все сеансы завершены. Отозваны устройства, \
                 которые ни разу не открывали хранилище:\n\
                 Your ConsoleCrypt account password was reset and every session was signed out. \
                 Devices that never unlocked the vault were revoked:\n\n{list}\n\n\
                 Если сброс сделали не вы, ссылка ниже отзовёт новые неподтверждённые \
                 устройства, вошедшие после сброса; затем снова сбросьте пароль.\n\
                 If you did not reset it, the link below revokes new unconfirmed devices that \
                 signed in after the reset; then reset the password again.{}{}",
                deny_link(public_url, token),
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
    fn all_templates_declare_utf8_mime_on_the_wire() {
        let from = "ConsoleCrypt <no-reply@example.org>".parse().unwrap();
        let token = format!("cct_{}", uuid::Uuid::new_v4().simple());
        let url = Some("https://example.org");
        let messages = [
            templates::verify_email("a@example.org", &token, url),
            templates::password_reset("a@example.org", &token, false, url),
            templates::password_reset("a@example.org", &token, true, url),
            templates::device_revoked("a@example.org", "Мой ноутбук", url),
            templates::password_changed("a@example.org", url),
            templates::new_device(
                "a@example.org",
                &templates::NewDeviceInfo {
                    name: "Ноутбук",
                    platform: "linux",
                    client_version: Some("0.8.6"),
                    at: chrono::Utc::now(),
                    ip: Some("192.0.2.1".parse().unwrap()),
                },
                "ccd_x",
                url,
            ),
            templates::new_device_summary("a@example.org", url),
            templates::envelope_abuse("a@example.org", "Ноутбук", "ccd_x", url),
            templates::password_changed_new_device("a@example.org", "Ноутбук", "ccd_x", url),
            templates::password_reset_completed("a@example.org", &["Ноутбук".into()], "ccd_x", url),
        ];
        for msg in messages {
            let wire = String::from_utf8(build_message(&from, &msg).unwrap().formatted()).unwrap();
            let (headers, _) = wire.split_once("\r\n\r\n").unwrap();
            // Decoding bytes as UTF-8 in a test is insufficient: email clients
            // need both MIME and an explicit charset to choose that decoder.
            assert!(headers.lines().any(|line| line == "MIME-Version: 1.0"));
            assert!(headers.lines().any(|line| {
                line.eq_ignore_ascii_case("Content-Type: text/plain; charset=utf-8")
            }));
        }
    }

    #[test]
    fn deny_links_carry_the_token_in_the_fragment() {
        let m =
            templates::envelope_abuse("a@example.org", "d", "ccd_TOKEN", Some("https://x.test/"));
        assert!(m
            .body
            .contains("https://x.test/account#action=deny-device&token=ccd_TOKEN"));
        let m = templates::envelope_abuse("a@example.org", "d", "ccd_TOKEN", None);
        assert!(!m.body.contains("ccd_TOKEN"));
    }

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
        let token = format!("cct_{}", uuid::Uuid::new_v4().simple());
        let msg = templates::verify_email("a@example.org", &token, None);
        let expected_body = msg.body.replace('\n', "\r\n");
        mailer.send(msg).await.unwrap();
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let path = entries[0].as_ref().unwrap().path();
        let content = std::fs::read_to_string(&path).unwrap();
        // UTF-8 templates are MIME/base64 encoded by lettre. Check the
        // decoded wire body, not whether an ASCII token survived encoding.
        use base64::Engine as _;
        let (headers, body) = content.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(headers.contains("Content-Transfer-Encoding: base64"));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.split_whitespace().collect::<String>())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), expected_body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
