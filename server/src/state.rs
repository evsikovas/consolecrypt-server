// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Shared application state.

use crate::config::Config;
use crate::crypto::PasswordHasher;
use crate::events::Events;
use crate::mail::{self, Mailer};
use crate::ratelimit::RateLimiters;
use cc_protocol::DeviceId;
use sqlx::PgPool;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct AppState(Arc<Inner>);

#[derive(Debug)]
pub struct Inner {
    pub db: PgPool,
    pub config: Config,
    pub events: Events,
    pub mailer: Arc<dyn Mailer>,
    pub limits: RateLimiters,
    pub passwords: PasswordHasher,
    /// Last time `devices.last_seen_at` was written per device (throttling).
    device_seen: Mutex<HashMap<DeviceId, Instant>>,
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// `last_seen_at` is written at most this often per device.
const LAST_SEEN_RESOLUTION: Duration = Duration::from_secs(60);

impl AppState {
    /// Build the state and start background tasks (event listener, limiter
    /// housekeeping).
    pub async fn new(config: Config, db: PgPool) -> anyhow::Result<Self> {
        let mailer = mail::from_config(&config.mail)?;
        Self::with_mailer(config, db, mailer).await
    }

    pub async fn with_mailer(
        config: Config,
        db: PgPool,
        mailer: Arc<dyn Mailer>,
    ) -> anyhow::Result<Self> {
        let events = Events::start(config.event_bus, &db).await?;
        let state = AppState(Arc::new(Inner {
            limits: RateLimiters::new(&config.rate_limits),
            passwords: PasswordHasher::new(&config.password_hashing)?,
            events,
            mailer,
            db,
            config,
            device_seen: Mutex::new(HashMap::new()),
        }));
        let weak = Arc::downgrade(&state.0);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                inner.limits.housekeeping();
                inner
                    .device_seen
                    .lock()
                    .expect("lock")
                    .retain(|_, t| t.elapsed() < LAST_SEEN_RESOLUTION);
            }
        });
        Ok(state)
    }

    /// Whether `last_seen_at` of `device` should be written now.
    pub fn should_touch_device(&self, device: DeviceId) -> bool {
        let mut seen = self.device_seen.lock().expect("lock");
        match seen.get(&device) {
            Some(t) if t.elapsed() < LAST_SEEN_RESOLUTION => false,
            _ => {
                seen.insert(device, Instant::now());
                true
            }
        }
    }
}
