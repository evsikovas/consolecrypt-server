// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Message templates: every message is rendered from one [`Letter`] into a
//! plain-text part and an HTML part (multipart/alternative), in the
//! configured language (`CC_MAIL_LANGUAGE`).
//!
//! * Codes work everywhere: they are always shown for pasting into the app.
//! * A button/link to the account page is added only when `CC_PUBLIC_URL`
//!   is set (the operator's website, or this server with `CC_WEB_ACCOUNT`).
//!   Without it messages never mention a web page. Codes in links sit in the
//!   URL fragment, so they never reach HTTP access logs.
//! * The server never derives URLs from request headers (`Host` /
//!   `X-Forwarded-Host`): an attacker could otherwise point reset links at
//!   their own site.
//! * Everything interpolated into HTML is escaped (device names, invitation
//!   notes and similar values are chosen by users).

use super::{MailKind, MailMessage};
use crate::config::MailLanguage;
use std::time::Duration;

/// What templates need from the configuration.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    /// Base URL of the account page (`<url>/account`), if there is one.
    pub public_url: Option<&'a str>,
    pub language: MailLanguage,
}

impl<'a> Ctx<'a> {
    pub fn new(config: &'a crate::config::Config) -> Self {
        Self {
            public_url: config
                .public_url
                .as_deref()
                .map(|u| u.trim_end_matches('/'))
                .filter(|u| !u.is_empty()),
            language: config.mail.language,
        }
    }

    fn ru(&self) -> bool {
        self.language == MailLanguage::Ru
    }

    fn account_link(&self, action: &str, token: &str) -> Option<String> {
        self.public_url
            .map(|url| format!("{url}/account#action={action}&token={token}"))
    }

    /// "This wasn't me" button of the device-protection mails (protocol
    /// 1.7), or the manual steps when there is no account page.
    fn deny(&self, token: &str, letter: &mut Letter) {
        match self.account_link("deny-device", token) {
            Some(url) => {
                letter.action = Some((
                    if self.ru() {
                        "Это не я — отозвать устройство"
                    } else {
                        "This wasn't me — revoke the device"
                    }
                    .into(),
                    url,
                ));
            }
            None => letter.notes.push(
                if self.ru() {
                    "Если это не вы, отзовите устройство на доверенном устройстве и смените \
                     пароль аккаунта."
                } else {
                    "If this wasn't you, revoke the device on a trusted device and change your \
                     account password."
                }
                .into(),
            ),
        }
    }
}

pub fn verify_email(ctx: Ctx<'_>, to: &str, token: &str, valid_for: Duration) -> MailMessage {
    let link = ctx.account_link("verify", token);
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — подтвердите email".into(),
            preheader: "Код подтверждения адреса для ConsoleCrypt".into(),
            title: "Подтвердите email".into(),
            intro: vec!["Этот адрес указан при регистрации аккаунта ConsoleCrypt.".into()],
            code_caption: code_caption_ru(link.is_some(), "код"),
            action: link.map(|url| ("Подтвердить email".into(), url)),
            code: Some(token.into()),
            notes: vec![
                format!(
                    "Код действует {} и подходит для одного подтверждения.",
                    duration_ru(valid_for)
                ),
                "Если вы не регистрировались в ConsoleCrypt, просто проигнорируйте это письмо."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — confirm your email".into(),
            preheader: "Your ConsoleCrypt email confirmation code".into(),
            title: "Confirm your email".into(),
            intro: vec!["This address was used to create a ConsoleCrypt account.".into()],
            code_caption: code_caption_en(link.is_some(), "code"),
            action: link.map(|url| ("Confirm email".into(), url)),
            code: Some(token.into()),
            notes: vec![
                format!(
                    "The code is valid for {} and can be used once.",
                    duration_en(valid_for)
                ),
                "If you did not sign up for ConsoleCrypt, just ignore this message.".into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(ctx, MailKind::VerifyEmail, to)
}

pub fn password_reset(
    ctx: Ctx<'_>,
    to: &str,
    token: &str,
    recovery: bool,
    valid_for: Duration,
) -> MailMessage {
    // The account page handles "reset" only; account recovery codes go to the app.
    let link = (!recovery)
        .then(|| ctx.account_link("reset", token))
        .flatten();
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — восстановление доступа".into(),
            preheader: "Одноразовый код для смены пароля аккаунта ConsoleCrypt".into(),
            title: "Смена пароля аккаунта".into(),
            intro: vec!["Получен запрос на смену пароля вашего аккаунта ConsoleCrypt.".into()],
            code_caption: code_caption_ru(link.is_some(), "одноразовый код"),
            action: link.map(|url| ("Задать новый пароль".into(), url)),
            code: Some(token.into()),
            notes: vec![
                format!(
                    "Код действует {}. После смены пароля все сеансы будут завершены.",
                    duration_ru(valid_for)
                ),
                "Смена пароля аккаунта не открывает хранилище: для него по-прежнему нужны \
                 парольная фраза хранилища, ключ восстановления или доверенное устройство."
                    .into(),
                "Если вы не запрашивали смену пароля, проигнорируйте это письмо — пароль \
                 останется прежним."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — reset your account password".into(),
            preheader: "One-time code to change your ConsoleCrypt account password".into(),
            title: "Reset your account password".into(),
            intro: vec![
                "We received a request to change your ConsoleCrypt account password.".into(),
            ],
            code_caption: code_caption_en(link.is_some(), "one-time code"),
            action: link.map(|url| ("Set a new password".into(), url)),
            code: Some(token.into()),
            notes: vec![
                format!(
                    "The code is valid for {}. Changing the password signs out all sessions.",
                    duration_en(valid_for)
                ),
                "Resetting the account password does not unlock your vault: you still need \
                 the vault passphrase, your Recovery Key or a trusted device."
                    .into(),
                "If you did not request this, ignore this message — your password stays the same."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(
        ctx,
        if recovery {
            MailKind::AccountRecovery
        } else {
            MailKind::PasswordReset
        },
        to,
    )
}

/// Many failed sign-ins to the account from many networks (security audit
/// S2, TR-8); at most one a day.
pub fn failed_logins(ctx: Ctx<'_>, to: &str) -> MailMessage {
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — много неудачных попыток входа".into(),
            preheader: "Кто-то подбирает пароль к вашему аккаунту ConsoleCrypt".into(),
            title: "Много неудачных попыток входа".into(),
            intro: vec![
                "Кто-то многократно пытается войти в ваш аккаунт ConsoleCrypt с неверным паролем."
                    .into(),
                "Сервер временно ограничил вход с новых устройств. Устройства, на которых вы уже \
                 входили, по-прежнему могут войти."
                    .into(),
            ],
            notes: vec![
                "Если это были не вы, задайте длинный уникальный пароль аккаунта и проверьте \
                 список устройств."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — many failed sign-in attempts".into(),
            preheader: "Someone is guessing your ConsoleCrypt account password".into(),
            title: "Many failed sign-in attempts".into(),
            intro: vec![
                "Someone is repeatedly trying to sign in to your ConsoleCrypt account with a \
                 wrong password."
                    .into(),
                "The server has temporarily limited sign-ins from new devices; the devices you \
                 already use can still sign in."
                    .into(),
            ],
            notes: vec![
                "If this was not you, use a long unique account password and review your devices."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(ctx, MailKind::FailedLogins, to)
}

pub fn device_revoked(ctx: Ctx<'_>, to: &str, device_name: &str) -> MailMessage {
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — устройство отключено".into(),
            preheader: format!("Устройство «{device_name}» больше не синхронизируется"),
            title: "Устройство отключено".into(),
            intro: vec![format!(
                "Устройство «{device_name}» отключено от вашего аккаунта и больше не \
                 синхронизируется."
            )],
            notes: vec![
                "Если это сделали не вы, войдите с доверенного устройства, проверьте список \
                 устройств и смените пароль аккаунта."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — a device was removed".into(),
            preheader: format!("“{device_name}” can no longer sync"),
            title: "A device was removed".into(),
            intro: vec![format!(
                "The device “{device_name}” was removed from your account and can no longer sync."
            )],
            notes: vec![
                "If this was not you, sign in on a trusted device, review your devices and \
                 change your account password."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(ctx, MailKind::DeviceRevoked, to)
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

pub fn new_device(ctx: Ctx<'_>, to: &str, info: &NewDeviceInfo<'_>, token: &str) -> MailMessage {
    let at = info.at.format("%Y-%m-%d %H:%M UTC").to_string();
    let version = info.client_version.unwrap_or("—").to_owned();
    let ip = info
        .ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "—".to_owned());
    let mut letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — вход с нового устройства".into(),
            preheader: format!("В аккаунт вошло устройство «{}»", info.name),
            title: "Вход с нового устройства".into(),
            intro: vec!["В ваш аккаунт ConsoleCrypt вошло новое устройство.".into()],
            facts: vec![
                ("Устройство".into(), format!("«{}»", info.name)),
                ("Платформа".into(), info.platform.into()),
                ("Версия".into(), version),
                ("Время".into(), at),
                ("IP".into(), ip),
            ],
            notes: vec![
                "Если это вы — ничего делать не нужно. Первые дни новое устройство не может \
                 отзывать ваши доверенные устройства."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — new device signed in".into(),
            preheader: format!("“{}” signed in to your account", info.name),
            title: "New device signed in".into(),
            intro: vec!["A new device signed in to your ConsoleCrypt account.".into()],
            facts: vec![
                ("Device".into(), format!("“{}”", info.name)),
                ("Platform".into(), info.platform.into()),
                ("Version".into(), version),
                ("Time".into(), at),
                ("IP".into(), ip),
            ],
            notes: vec![
                "If this was you, there is nothing to do. For its first days a new device \
                 cannot revoke your trusted devices."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    ctx.deny(token, &mut letter);
    letter.render(ctx, MailKind::NewDevice, to)
}

/// Sent once when an hour has more sign-ins than individual mails.
pub fn new_device_summary(ctx: Ctx<'_>, to: &str) -> MailMessage {
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — много входов с новых устройств".into(),
            preheader: "За последний час в аккаунт вошло много новых устройств".into(),
            title: "Много входов с новых устройств".into(),
            intro: vec![
                "За последний час в ваш аккаунт ConsoleCrypt вошло много новых устройств. \
                 Отдельных писем о них в этот час больше не будет."
                    .into(),
            ],
            notes: vec![
                "Проверьте список устройств на доверенном устройстве и, если это не вы, смените \
                 пароль аккаунта."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — many new device sign-ins".into(),
            preheader: "Many new devices signed in to your account in the last hour".into(),
            title: "Many new device sign-ins".into(),
            intro: vec![
                "Many new devices signed in to your ConsoleCrypt account in the last hour. No \
                 further mails are sent for them this hour."
                    .into(),
            ],
            notes: vec![
                "Review your devices on a trusted device and, if this wasn't you, change your \
                 account password."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(ctx, MailKind::NewDevice, to)
}

pub fn envelope_abuse(ctx: Ctx<'_>, to: &str, device_name: &str, token: &str) -> MailMessage {
    let mut letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — повторные попытки доступа к хранилищу".into(),
            preheader: format!("Устройство «{device_name}» многократно запрашивает доступ"),
            title: "Повторные попытки доступа к хранилищу".into(),
            intro: vec![format!(
                "Кто-то многократно запрашивает доступ к хранилищу с устройства «{device_name}». \
                 Сервер временно ограничил такие запросы."
            )],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — repeated vault access attempts".into(),
            preheader: format!("“{device_name}” keeps requesting vault access"),
            title: "Repeated vault access attempts".into(),
            intro: vec![format!(
                "Someone is repeatedly requesting access to your vault from the device \
                 “{device_name}”. The server has temporarily limited these requests."
            )],
            ..Letter::default()
        }
    };
    ctx.deny(token, &mut letter);
    letter.render(ctx, MailKind::EnvelopeAbuse, to)
}

/// The account password was changed from a device in quarantine: trusted
/// devices stay signed in (TR-7).
pub fn password_changed_new_device(
    ctx: Ctx<'_>,
    to: &str,
    device_name: &str,
    token: &str,
) -> MailMessage {
    let mut letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — пароль изменён с нового устройства".into(),
            preheader: format!("Пароль аккаунта изменён с устройства «{device_name}»"),
            title: "Пароль изменён с нового устройства".into(),
            intro: vec![format!(
                "Пароль аккаунта ConsoleCrypt изменён с нового устройства «{device_name}». \
                 Ваши доверенные устройства остались в аккаунте."
            )],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — password changed from a new device".into(),
            preheader: format!("Your account password was changed from “{device_name}”"),
            title: "Password changed from a new device".into(),
            intro: vec![format!(
                "Your ConsoleCrypt account password was changed from the new device \
                 “{device_name}”. Your trusted devices stay signed in."
            )],
            ..Letter::default()
        }
    };
    ctx.deny(token, &mut letter);
    letter.notes.push(
        if ctx.ru() {
            "После отзыва смените пароль через «Забыли пароль?»."
        } else {
            "After revoking, reset the password via “Forgot password?”."
        }
        .into(),
    );
    letter.render(ctx, MailKind::PasswordChanged, to)
}

/// TR-13: after a password reset, with the devices it revoked.
pub fn password_reset_completed(
    ctx: Ctx<'_>,
    to: &str,
    revoked: &[String],
    token: &str,
) -> MailMessage {
    let names = if revoked.is_empty() {
        vec!["—".to_owned()]
    } else if ctx.ru() {
        revoked.iter().map(|n| format!("«{n}»")).collect()
    } else {
        revoked.iter().map(|n| format!("“{n}”")).collect()
    };
    let mut letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — пароль аккаунта сброшен".into(),
            preheader: "Пароль аккаунта сброшен, все сеансы завершены".into(),
            title: "Пароль аккаунта сброшен".into(),
            intro: vec![
                "Пароль аккаунта ConsoleCrypt сброшен, все сеансы завершены. Отозваны \
                 устройства, которые ни разу не открывали хранилище:"
                    .into(),
            ],
            items: names,
            notes: vec![
                "Если сброс сделали не вы, кнопка ниже отзовёт новые неподтверждённые \
                 устройства, вошедшие после сброса; затем снова сбросьте пароль."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — account password was reset".into(),
            preheader: "Your account password was reset and every session was signed out".into(),
            title: "Account password was reset".into(),
            intro: vec![
                "Your ConsoleCrypt account password was reset and every session was signed \
                 out. Devices that never unlocked the vault were revoked:"
                    .into(),
            ],
            items: names,
            notes: vec![
                "If you did not reset it, the button below revokes new unconfirmed devices that \
                 signed in after the reset; then reset the password again."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    if ctx.public_url.is_some() {
        ctx.deny(token, &mut letter);
    } else {
        // No button to point at: the manual steps replace the hint about it.
        letter.notes = vec![if ctx.ru() {
            "Если сброс сделали не вы, отзовите новые неподтверждённые устройства на \
             доверенном устройстве и снова сбросьте пароль."
        } else {
            "If you did not reset it, revoke new unconfirmed devices on a trusted device and \
             reset the password again."
        }
        .into()];
    }
    letter.render(ctx, MailKind::PasswordResetCompleted, to)
}

/// Teams (protocol 1.9): an account was invited into a team. The team name
/// is end-to-end encrypted, so only the inviter, the role and the inviter's
/// plain-text note can be shown.
pub fn team_invitation(
    ctx: Ctx<'_>,
    to: &str,
    inviter: &str,
    role: &str,
    note: Option<&str>,
) -> MailMessage {
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — приглашение в команду".into(),
            preheader: format!("{inviter} приглашает вас в команду ConsoleCrypt"),
            title: "Приглашение в команду".into(),
            intro: vec![format!(
                "{inviter} приглашает вас в команду ConsoleCrypt (роль: {role})."
            )],
            facts: note
                .map(|n| vec![("Комментарий приглашения".into(), n.to_owned())])
                .unwrap_or_default(),
            notes: vec![
                format!(
                    "Откройте ConsoleCrypt → Настройки → Команды, примите приглашение и сверьте \
                     код с {inviter} — по телефону или лично. Доступ появится только после \
                     того, как коды совпадут."
                ),
                "Если вы не ждали приглашения, просто отклоните его.".into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — team invitation".into(),
            preheader: format!("{inviter} invited you to a ConsoleCrypt team"),
            title: "Team invitation".into(),
            intro: vec![format!(
                "{inviter} invited you to a ConsoleCrypt team (role: {role})."
            )],
            facts: note
                .map(|n| vec![("Invitation note".into(), n.to_owned())])
                .unwrap_or_default(),
            notes: vec![
                format!(
                    "Open ConsoleCrypt → Settings → Teams, accept the invitation and compare the \
                     code with {inviter} by phone or in person. Access is granted only after the \
                     codes match."
                ),
                "If you did not expect this, decline it.".into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(ctx, MailKind::TeamInvitation, to)
}

pub fn password_changed(ctx: Ctx<'_>, to: &str) -> MailMessage {
    let letter = if ctx.ru() {
        Letter {
            subject: "ConsoleCrypt — пароль изменён".into(),
            preheader: "Пароль аккаунта ConsoleCrypt изменён".into(),
            title: "Пароль аккаунта изменён".into(),
            intro: vec![
                "Пароль вашего аккаунта ConsoleCrypt изменён, остальные сеансы завершены.".into(),
            ],
            notes: vec![
                "Если это сделали не вы, немедленно восстановите доступ через «Забыли пароль?» \
                 в приложении."
                    .into(),
            ],
            ..Letter::default()
        }
    } else {
        Letter {
            subject: "ConsoleCrypt — your password was changed".into(),
            preheader: "Your ConsoleCrypt account password was changed".into(),
            title: "Your password was changed".into(),
            intro: vec![
                "Your ConsoleCrypt account password was changed and other sessions were signed out."
                    .into(),
            ],
            notes: vec![
                "If this was not you, reset your password right away with “Forgot password?” in \
                 the app."
                    .into(),
            ],
            ..Letter::default()
        }
    };
    letter.render(ctx, MailKind::PasswordChanged, to)
}

fn code_caption_ru(has_link: bool, what: &str) -> String {
    if has_link {
        format!("Или вставьте {what} в приложение ConsoleCrypt:")
    } else {
        format!("Вставьте {what} в приложение ConsoleCrypt:")
    }
}

fn code_caption_en(has_link: bool, what: &str) -> String {
    if has_link {
        format!("Or paste this {what} into the ConsoleCrypt app:")
    } else {
        format!("Paste this {what} into the ConsoleCrypt app:")
    }
}

/// "48 часов", "1 час", "30 минут".
pub(crate) fn duration_ru(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 && secs % 3600 == 0 {
        let h = secs / 3600;
        format!("{h} {}", plural_ru(h, "час", "часа", "часов"))
    } else {
        let m = secs.div_ceil(60).max(1);
        format!("{m} {}", plural_ru(m, "минуту", "минуты", "минут"))
    }
}

fn plural_ru<'a>(n: u64, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    match (n % 10, n % 100) {
        (1, r) if r != 11 => one,
        (2..=4, r) if !(12..=14).contains(&r) => few,
        _ => many,
    }
}

pub(crate) fn duration_en(d: Duration) -> String {
    let secs = d.as_secs();
    let (n, unit) = if secs >= 3600 && secs % 3600 == 0 {
        (secs / 3600, "hour")
    } else {
        (secs.div_ceil(60).max(1), "minute")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// One message, rendered as text and HTML.
#[derive(Default)]
struct Letter {
    subject: String,
    /// Inbox preview line (hidden in the HTML body).
    preheader: String,
    title: String,
    intro: Vec<String>,
    /// Labelled values (device details, invitation note).
    facts: Vec<(String, String)>,
    /// Bulleted list (revoked devices).
    items: Vec<String>,
    /// Button label and URL (account page), if any.
    action: Option<(String, String)>,
    code_caption: String,
    code: Option<String>,
    notes: Vec<String>,
}

impl Letter {
    fn footer(&self, ctx: Ctx<'_>) -> (String, String) {
        let auto = if ctx.ru() {
            "Это автоматическое письмо, отвечать на него не нужно."
        } else {
            "This is an automated message; please do not reply."
        };
        match ctx.public_url {
            Some(url) => {
                let label = if ctx.ru() {
                    "Сервер ConsoleCrypt"
                } else {
                    "ConsoleCrypt server"
                };
                let host = url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");
                (
                    format!("{label}: {url}\n{auto}"),
                    format!(
                        "{label}: <a href=\"{u}\" style=\"color:#6b7280;\">{h}</a><br>{auto}",
                        u = escape_html(url),
                        h = escape_html(host),
                        auto = escape_html(auto),
                    ),
                )
            }
            None => (
                format!("ConsoleCrypt\n{auto}"),
                format!("ConsoleCrypt<br>{}", escape_html(auto)),
            ),
        }
    }

    fn render(self, ctx: Ctx<'_>, kind: MailKind, to: &str) -> MailMessage {
        let (footer_text, footer_html) = self.footer(ctx);
        MailMessage {
            kind,
            to: to.to_owned(),
            body: self.render_text(&footer_text),
            html: Some(self.render_html(ctx, &footer_html)),
            subject: self.subject,
        }
    }

    fn render_text(&self, footer: &str) -> String {
        let mut out = format!("{}\n\n", self.title);
        for p in &self.intro {
            out.push_str(p);
            out.push_str("\n\n");
        }
        if !self.facts.is_empty() {
            for (label, value) in &self.facts {
                out.push_str(&format!("{label}: {value}\n"));
            }
            out.push('\n');
        }
        if !self.items.is_empty() {
            for item in &self.items {
                out.push_str(&format!("  • {item}\n"));
            }
            out.push('\n');
        }
        if let Some((label, url)) = &self.action {
            out.push_str(&format!("{label}:\n{url}\n\n"));
        }
        if let Some(code) = &self.code {
            // The code stands alone on its own line: easy to select and copy.
            out.push_str(&format!("{}\n{code}\n\n", self.code_caption));
        }
        for n in &self.notes {
            out.push_str(n);
            out.push_str("\n\n");
        }
        out.push_str(footer);
        out.push('\n');
        out
    }

    fn render_html(&self, ctx: Ctx<'_>, footer: &str) -> String {
        const FONT: &str =
            "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
        const MONO: &str = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";
        let lang = if ctx.ru() { "ru" } else { "en" };
        let mut rows = String::new();
        for p in &self.intro {
            rows.push_str(&format!(
                "<tr><td style=\"padding:12px 32px 0;font:400 15px/1.6 {FONT};color:#374151;\">{}</td></tr>",
                escape_html(p)
            ));
        }
        if !self.facts.is_empty() {
            let mut facts = String::new();
            for (label, value) in &self.facts {
                facts.push_str(&format!(
                    "<tr><td style=\"padding:3px 16px 3px 0;font:400 13px/1.5 {FONT};color:#6b7280;\
                     vertical-align:top;white-space:nowrap;\">{label}</td>\
                     <td style=\"padding:3px 0;font:500 14px/1.5 {FONT};color:#111827;\
                     word-break:break-word;\">{value}</td></tr>",
                    label = escape_html(label),
                    value = escape_html(value),
                ));
            }
            rows.push_str(&format!(
                "<tr><td style=\"padding:16px 32px 0;\">\
                 <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">{facts}</table>\
                 </td></tr>"
            ));
        }
        if !self.items.is_empty() {
            let items: String = self
                .items
                .iter()
                .map(|item| format!("<li style=\"margin:2px 0;\">{}</li>", escape_html(item)))
                .collect();
            rows.push_str(&format!(
                "<tr><td style=\"padding:8px 32px 0;font:500 14px/1.6 {FONT};color:#111827;\">\
                 <ul style=\"margin:0;padding-left:20px;\">{items}</ul></td></tr>"
            ));
        }
        if let Some((label, url)) = &self.action {
            rows.push_str(&format!(
                "<tr><td style=\"padding:24px 32px 4px;\">\
                 <a href=\"{url}\" style=\"display:inline-block;background:#2563eb;color:#ffffff;\
                 text-decoration:none;font:600 15px/1 {FONT};padding:14px 24px;border-radius:8px;\">{label}</a>\
                 </td></tr>",
                url = escape_html(url),
                label = escape_html(label),
            ));
        }
        if let Some(code) = &self.code {
            rows.push_str(&format!(
                "<tr><td style=\"padding:20px 32px 0;font:400 14px/1.5 {FONT};color:#6b7280;\">{caption}</td></tr>\
                 <tr><td style=\"padding:8px 32px 0;\">\
                 <div style=\"font:500 15px/1.5 {MONO};color:#111827;background:#f3f4f6;\
                 border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;word-break:break-all;\">{code}</div>\
                 </td></tr>",
                caption = escape_html(&self.code_caption),
                code = escape_html(code),
            ));
        }
        for n in &self.notes {
            rows.push_str(&format!(
                "<tr><td style=\"padding:16px 32px 0;font:400 13px/1.6 {FONT};color:#6b7280;\">{}</td></tr>",
                escape_html(n)
            ));
        }
        format!(
            "<!DOCTYPE html>\
<html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"color-scheme\" content=\"light\"><meta name=\"supported-color-schemes\" content=\"light\">\
<title>{subject}</title></head>\
<body style=\"margin:0;padding:0;background:#f4f5f7;\">\
<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;\">{preheader}</div>\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"background:#f4f5f7;\">\
<tr><td align=\"center\" style=\"padding:32px 12px;\">\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" \
style=\"max-width:520px;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;\">\
<tr><td style=\"padding:28px 32px 0;font:700 15px/1.4 {FONT};color:#111827;letter-spacing:0.02em;\">ConsoleCrypt</td></tr>\
<tr><td style=\"padding:16px 32px 0;font:600 22px/1.3 {FONT};color:#111827;\">{title}</td></tr>\
{rows}\
<tr><td style=\"padding:28px 32px 28px;\">\
<div style=\"border-top:1px solid #e5e7eb;padding-top:16px;font:400 12px/1.6 {FONT};color:#9ca3af;\">{footer}</div>\
</td></tr></table></td></tr></table></body></html>",
            subject = escape_html(&self.subject),
            preheader = escape_html(&self.preheader),
            title = escape_html(&self.title),
        )
    }
}

/// Minimal HTML escaping for text and attribute values.
pub(crate) fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(url: Option<&str>, language: MailLanguage) -> Ctx<'_> {
        Ctx {
            public_url: url,
            language,
        }
    }

    const TOKEN: &str = "cct_abcDEF123-_xyz";
    const DAY2: Duration = Duration::from_secs(48 * 3600);
    const URL: &str = "https://consolecrypt.dev";

    #[test]
    fn mail_without_an_account_page_never_mentions_one() {
        let m = verify_email(ctx(None, MailLanguage::Ru), "a@example.org", TOKEN, DAY2);
        let html = m.html.as_deref().unwrap();
        for text in [m.body.as_str(), html] {
            assert!(!text.contains("кабинет"), "{text}");
            assert!(!text.contains("/account"));
            assert!(text.contains(TOKEN));
            assert!(text.contains("48 часов"));
            assert!(!text.contains("-- "), "no raw signature delimiter");
        }
        assert!(m.body.contains("Вставьте код в приложение ConsoleCrypt:"));
        assert!(!html.contains("<a href"));
    }

    #[test]
    fn account_page_gets_a_button_and_a_fragment_link() {
        let m = verify_email(
            ctx(Some(URL), MailLanguage::Ru),
            "a@example.org",
            TOKEN,
            DAY2,
        );
        let link = format!("{URL}/account#action=verify&token={TOKEN}");
        assert!(m.body.contains(&link));
        assert!(m.body.contains("Или вставьте код"));
        let html = m.html.unwrap();
        assert!(html.contains(&format!("href=\"{}\"", escape_html(&link))));
        assert!(html.contains("Подтвердить email"));
        assert!(html.contains("Сервер ConsoleCrypt"));
        // The code is still on its own line in the text part.
        assert!(m.body.lines().any(|l| l == TOKEN));
    }

    #[test]
    fn recovery_codes_have_no_web_link() {
        let c = ctx(Some(URL), MailLanguage::Ru);
        let reset = password_reset(c, "a@example.org", TOKEN, false, Duration::from_secs(3600));
        assert!(reset.body.contains("action=reset"));
        assert!(reset.body.contains("1 час"));
        let recovery = password_reset(c, "a@example.org", TOKEN, true, Duration::from_secs(3600));
        assert!(!recovery.body.contains("/account"));
        assert_eq!(recovery.kind, MailKind::AccountRecovery);
    }

    #[test]
    fn deny_links_carry_the_token_in_the_fragment_or_give_manual_steps() {
        for language in [MailLanguage::Ru, MailLanguage::En] {
            let m = envelope_abuse(
                ctx(Some("https://x.test"), language),
                "a@example.org",
                "d",
                "ccd_TOKEN",
            );
            assert!(m
                .body
                .contains("https://x.test/account#action=deny-device&token=ccd_TOKEN"));
            let m = envelope_abuse(ctx(None, language), "a@example.org", "d", "ccd_TOKEN");
            assert!(!m.body.contains("ccd_TOKEN"));
            assert!(!m.html.unwrap().contains("ccd_TOKEN"));
            assert!(m.body.contains(if language == MailLanguage::Ru {
                "отзовите устройство на доверенном устройстве"
            } else {
                "revoke the device on a trusted device"
            }));
        }
    }

    #[test]
    fn new_device_lists_the_details() {
        let info = NewDeviceInfo {
            name: "Stranger <laptop>",
            platform: "cli",
            client_version: Some("0.9.2"),
            at: chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
            ip: Some("192.0.2.1".parse().unwrap()),
        };
        let m = new_device(
            ctx(Some(URL), MailLanguage::En),
            "a@example.org",
            &info,
            "ccd_X",
        );
        assert_eq!(m.kind, MailKind::NewDevice);
        for needle in [
            "Stranger <laptop>",
            "Platform: cli",
            "0.9.2",
            "UTC",
            "192.0.2.1",
        ] {
            assert!(m.body.contains(needle), "{needle}");
        }
        assert!(m.body.contains("token=ccd_X"));
        let html = m.html.unwrap();
        assert!(html.contains("Stranger &lt;laptop&gt;"));
        assert!(!html.contains("<laptop>"));
    }

    #[test]
    fn password_reset_completed_lists_revoked_devices() {
        let m = password_reset_completed(
            ctx(Some(URL), MailLanguage::Ru),
            "a@example.org",
            &["Never trusted".into(), "Old phone".into()],
            "ccd_X",
        );
        assert!(m.body.contains("  • «Never trusted»\n  • «Old phone»"));
        assert!(m.body.contains("кнопка ниже"));
        assert!(m.body.contains("#action=deny-device&token=ccd_X"));
        let empty =
            password_reset_completed(ctx(None, MailLanguage::En), "a@example.org", &[], "t");
        assert!(empty.body.contains("  • —"));
        assert!(
            !empty.body.contains("button below"),
            "no button without a page"
        );
    }

    #[test]
    fn user_controlled_text_is_escaped_in_html() {
        let m = device_revoked(
            ctx(None, MailLanguage::En),
            "a@example.org",
            "<img src=x onerror=alert(1)>\"&",
        );
        let html = m.html.unwrap();
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;&quot;&amp;"));
        let invite = team_invitation(
            ctx(None, MailLanguage::Ru),
            "a@example.org",
            "<b>boss</b>@example.org",
            "editor",
            Some("<script>x</script>"),
        );
        let html = invite.html.unwrap();
        assert!(!html.contains("<script>") && !html.contains("<b>"));
        assert!(invite.body.contains("роль: editor"));
        assert!(
            invite.body.contains("<script>x</script>"),
            "plain text stays verbatim"
        );
    }

    #[test]
    fn english_variants() {
        let m = verify_email(ctx(None, MailLanguage::En), "a@example.org", TOKEN, DAY2);
        assert_eq!(m.subject, "ConsoleCrypt — confirm your email");
        assert!(m
            .body
            .contains("Paste this code into the ConsoleCrypt app:"));
        assert!(m.body.contains("48 hours"));
        let c = password_changed(ctx(None, MailLanguage::En), "a@example.org");
        assert!(c.html.unwrap().contains("lang=\"en\""));
        let f = failed_logins(ctx(None, MailLanguage::En), "a@example.org");
        assert!(!f.body.contains("Кто-то"), "one language per message");
    }

    #[test]
    fn durations() {
        let s = Duration::from_secs;
        assert_eq!(duration_ru(s(3600)), "1 час");
        assert_eq!(duration_ru(s(2 * 3600)), "2 часа");
        assert_eq!(duration_ru(s(5 * 3600)), "5 часов");
        assert_eq!(duration_ru(s(21 * 3600)), "21 час");
        assert_eq!(duration_ru(s(48 * 3600)), "48 часов");
        assert_eq!(duration_ru(s(11 * 3600)), "11 часов");
        assert_eq!(duration_ru(s(30 * 60)), "30 минут");
        assert_eq!(duration_ru(s(90)), "2 минуты");
        assert_eq!(duration_en(s(3600)), "1 hour");
        assert_eq!(duration_en(s(48 * 3600)), "48 hours");
        assert_eq!(duration_en(s(90 * 60)), "90 minutes");
    }
}
