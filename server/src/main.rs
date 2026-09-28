// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! `consolecrypt-server` binary: `serve` (default), `migrate`, `admin …`.

use clap::{Parser, Subcommand};
use consolecrypt_server::{admin, config::LogFormat, db, telemetry, Config};

#[derive(Debug, Parser)]
#[command(
    name = "consolecrypt-server",
    version,
    author = "Alexander Evsikov <i@evsikov.net>",
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        "\nAuthor: Alexander Evsikov <i@evsikov.net>",
        "\nLicense: AGPL-3.0-only (source: https://github.com/consolecrypt/consolecrypt)"
    ),
    after_help = "Author: Alexander Evsikov <i@evsikov.net> · License: AGPL-3.0-only",
    about = "ConsoleCrypt zero-knowledge sync server (AGPL-3.0-only)",
    long_about = "ConsoleCrypt zero-knowledge sync server.\n\n\
                  Configuration is read from CC_* environment variables (see .env.example)."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP/WebSocket server (default).
    Serve,
    /// Apply database migrations and exit.
    Migrate,
    /// Probe `GET /readyz` on the local listener; exit code 0 if ready.
    /// For container health checks (the runtime image has no curl).
    Healthcheck,
    /// Account administration for operators (no vault access, ever).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Print a single-use password-reset token (instances without SMTP).
    ResetToken {
        #[arg(long)]
        email: String,
    },
    /// Set a new account password read from stdin; signs out all sessions.
    SetPassword {
        #[arg(long)]
        email: String,
        /// Read the password from the first line of stdin (required, so it
        /// never appears in shell history or the process list).
        #[arg(long, required = true)]
        password_stdin: bool,
    },
    /// Mark an account's email as verified.
    VerifyEmail {
        #[arg(long)]
        email: String,
    },
    /// Disable an account and revoke its sessions.
    DisableUser {
        #[arg(long)]
        email: String,
    },
    /// Re-enable a disabled account.
    EnableUser {
        #[arg(long)]
        email: String,
    },
    /// List accounts (email, status, device and vault counts).
    ListUsers,
    /// After restoring the database from a backup: rotate vault epochs so
    /// clients detect the rollback and re-upload what the backup lacks.
    #[command(group(clap::ArgGroup::new("target").required(true).args(["vault", "all"])))]
    RotateEpoch {
        /// One vault id.
        #[arg(long)]
        vault: Option<cc_protocol::VaultId>,
        /// Every vault on this server.
        #[arg(long)]
        all: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if matches!(cli.command, Some(Command::Healthcheck)) {
        return healthcheck().await;
    }
    let config = Config::from_env()?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let _telemetry = telemetry::init_tracing(config.log_format);
            tracing::info!(config = ?config, "starting");
            consolecrypt_server::serve(config).await
        }
        Command::Migrate => {
            let _telemetry = telemetry::init_tracing(config.log_format);
            let pool = db::connect(&config).await?;
            db::migrate(&pool).await?;
            println!("migrations applied");
            Ok(())
        }
        Command::Healthcheck => unreachable!("handled above"),
        Command::Admin { command } => {
            let _telemetry = telemetry::init_tracing(LogFormat::Pretty);
            let pool = db::connect(&config).await?;
            run_admin(&pool, &config, command).await
        }
    }
}

async fn run_admin(pool: &sqlx::PgPool, config: &Config, cmd: AdminCommand) -> anyhow::Result<()> {
    match cmd {
        AdminCommand::ResetToken { email } => {
            let token = admin::reset_token(pool, config, &email).await?;
            println!("{token}");
            eprintln!(
                "Single-use password reset token (valid {} min). The user enters it in the client.",
                config.password_reset_ttl.as_secs() / 60
            );
        }
        AdminCommand::SetPassword { email, .. } => {
            let password = admin::read_password_stdin()?;
            let n = admin::set_password(pool, config, &email, &password).await?;
            println!("password updated; {n} session(s) revoked");
        }
        AdminCommand::VerifyEmail { email } => {
            admin::verify_email(pool, &email).await?;
            println!("email verified");
        }
        AdminCommand::DisableUser { email } => {
            admin::set_enabled(pool, &email, false).await?;
            println!("account disabled");
        }
        AdminCommand::EnableUser { email } => {
            admin::set_enabled(pool, &email, true).await?;
            println!("account enabled");
        }
        AdminCommand::RotateEpoch { vault, .. } => {
            let n = admin::rotate_epoch(pool, vault).await?;
            println!("rotated the epoch of {n} vault(s)");
        }
        AdminCommand::ListUsers => {
            for u in admin::list_users(pool).await? {
                println!(
                    "{}  {}  status={}  verified={}  devices={}  vaults={}",
                    u.id, u.email, u.status, u.email_verified, u.devices, u.vaults
                );
            }
        }
    }
    Ok(())
}

/// Minimal HTTP/1.1 probe without an HTTP client dependency.
async fn healthcheck() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listen: std::net::SocketAddr = std::env::var("CC_LISTEN_ADDR")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 8080)));
    let target = std::net::SocketAddr::from(([127, 0, 0, 1], listen.port()));
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(target).await?;
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await?;
        anyhow::Ok(buf[..n].starts_with(b"HTTP/1.1 200"))
    };
    match tokio::time::timeout(std::time::Duration::from_secs(3), probe).await {
        Ok(Ok(true)) => Ok(()),
        _ => anyhow::bail!("not ready"),
    }
}
