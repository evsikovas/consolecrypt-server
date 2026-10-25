// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Render every mail template to files for a visual check:
//!
//!   cargo run --example mail_preview -- <out-dir> [ru|en] [public-url]
//!
//! Writes `<n>-<kind>.html` and `<n>-<kind>.txt` with dummy codes. Without a
//! public URL the output is what a server without an account page sends.

use consolecrypt_server::config::MailLanguage;
use consolecrypt_server::mail::templates::{self, Ctx, NewDeviceInfo};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let out = std::path::PathBuf::from(args.next().unwrap_or_else(|| "mail-preview".into()));
    let language = match args.next().as_deref() {
        Some("en") => MailLanguage::En,
        _ => MailLanguage::Ru,
    };
    let public_url = args.next();
    let ctx = Ctx {
        public_url: public_url.as_deref().map(|u| u.trim_end_matches('/')),
        language,
    };
    let to = "user@example.org";
    let code = "cct_EXAMPLEcodeEXAMPLEcodeEXAMPLEcodeEXAMPLEc";
    let deny = "ccd_EXAMPLEcodeEXAMPLEcodeEXAMPLEcodeEXAMPLEc";
    let device = NewDeviceInfo {
        name: "Рабочий MacBook",
        platform: "macos",
        client_version: Some("0.9.2"),
        at: chrono::Utc::now(),
        ip: Some("192.0.2.10".parse()?),
    };
    std::fs::create_dir_all(&out)?;
    let messages = [
        templates::verify_email(ctx, to, code, Duration::from_secs(48 * 3600)),
        templates::password_reset(ctx, to, code, false, Duration::from_secs(3600)),
        templates::password_reset(ctx, to, code, true, Duration::from_secs(3600)),
        templates::failed_logins(ctx, to),
        templates::device_revoked(ctx, to, "Рабочий MacBook"),
        templates::password_changed(ctx, to),
        templates::new_device(ctx, to, &device, deny),
        templates::new_device_summary(ctx, to),
        templates::envelope_abuse(ctx, to, "Рабочий MacBook", deny),
        templates::password_changed_new_device(ctx, to, "Рабочий MacBook", deny),
        templates::password_reset_completed(ctx, to, &["Старый телефон".into()], deny),
        templates::team_invitation(ctx, to, "lead@example.org", "editor", Some("Ops")),
    ];
    for (i, m) in messages.into_iter().enumerate() {
        let name = format!("{:02}-{}", i + 1, m.kind.as_str());
        std::fs::write(
            out.join(format!("{name}.txt")),
            format!("Subject: {}\n\n{}", m.subject, m.body),
        )?;
        if let Some(html) = &m.html {
            std::fs::write(out.join(format!("{name}.html")), html)?;
        }
        println!("{name}: {}", m.subject);
    }
    Ok(())
}
