// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Database pool and migrations.

use crate::config::Config;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::time::Duration;

/// Migrations embedded at compile time (no database needed to build).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Connection options from the config (`CC_DATABASE_URL`, optionally with
/// `CC_DATABASE_PASSWORD` applied on top). Without either, sqlx falls back to
/// the libpq `PGPASSWORD` variable.
///
/// NEVER log the returned value: sqlx's `Debug` for it includes the password.
pub fn connect_options(config: &Config) -> anyhow::Result<PgConnectOptions> {
    use sqlx::ConnectOptions as _;
    let mut options = PgConnectOptions::from_str(&config.database_url)
        .map_err(|_| anyhow::anyhow!("CC_DATABASE_URL is not a valid PostgreSQL URL"))?
        .application_name("consolecrypt-server")
        // Statement text only (bound values are never logged by sqlx).
        .log_statements(log::LevelFilter::Trace)
        .log_slow_statements(log::LevelFilter::Warn, Duration::from_millis(500));
    if let Some(password) = &config.database_password {
        options = options.password(password);
    }
    Ok(options)
}

/// Connect, retrying with backoff for up to `CC_DATABASE_CONNECT_TIMEOUT_SECS`
/// so a server starting before its database does not crash-loop.
pub async fn connect(config: &Config) -> anyhow::Result<PgPool> {
    let options = connect_options(config)?;
    let deadline = std::time::Instant::now() + config.database_connect_timeout;
    let mut delay = Duration::from_millis(250);
    loop {
        match connect_with(options.clone(), config.database_max_connections).await {
            Ok(pool) => return Ok(pool),
            Err(err) if std::time::Instant::now() + delay < deadline => {
                tracing::warn!(error = %err, retry_in_ms = delay.as_millis() as u64, "database not reachable yet");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            Err(err) => return Err(err.context("cannot connect to the database")),
        }
    }
}

pub async fn connect_with(options: PgConnectOptions, max: u32) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    Ok(pool)
}

/// Records `cc_db_duration_seconds{op}` (PostgreSQL latency of a hot path)
/// when dropped.
#[derive(Debug)]
pub struct DbTimer {
    op: &'static str,
    started: std::time::Instant,
}

impl DbTimer {
    pub fn start(op: &'static str) -> Self {
        Self {
            op,
            started: std::time::Instant::now(),
        }
    }
}

impl Drop for DbTimer {
    fn drop(&mut self) {
        metrics::histogram!("cc_db_duration_seconds", "op" => self.op)
            .record(self.started.elapsed().as_secs_f64());
    }
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_applied_on_top_of_the_url() {
        let mut c = Config::for_tests("postgres://app@db.example.org:5432/consolecrypt");
        c.database_password = Some("p@ss:w/rd".into());
        let o = connect_options(&c).unwrap();
        assert_eq!(o.get_host(), "db.example.org");
        assert_eq!(o.get_username(), "app");
        assert_eq!(o.get_database(), Some("consolecrypt"));
        // The password has no getter; sqlx's Debug of PgConnectOptions DOES
        // print it — which is why connect options are never logged anywhere.
        assert!(format!("{o:?}").contains("p@ss:w/rd"));
    }

    #[tokio::test]
    async fn gives_up_after_the_connect_timeout() {
        let mut c = Config::for_tests("postgres://app@127.0.0.1:1/none");
        c.database_connect_timeout = Duration::from_millis(600);
        let started = std::time::Instant::now();
        assert!(connect(&c).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
