// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Realtime events (ADR-0201): a bus that fans events out across replicas and
//! a per-user hub that feeds local WebSocket connections.
//!
//! Events carry metadata only (ids, sequence numbers). They are hints —
//! delivery is at-most-once and clients pull after reconnecting.

pub mod ws;

use crate::config::EventBusKind;
use cc_protocol::events::ServerEvent;
use cc_protocol::{UserId, VaultId};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

/// PostgreSQL NOTIFY channel.
pub const CHANNEL: &str = "cc_events";
/// Per-user buffer; a connection that falls further behind is disconnected.
const USER_CHANNEL_CAPACITY: usize = 256;

/// What travels on the bus: the event plus the users it is addressed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusMessage {
    pub users: Vec<UserId>,
    pub event: ServerEvent,
}

/// Local fanout to this replica's WebSocket connections.
#[derive(Default)]
pub struct Hub {
    channels: Mutex<HashMap<UserId, broadcast::Sender<Arc<ServerEvent>>>>,
}

impl fmt::Debug for Hub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hub")
    }
}

impl Hub {
    pub fn subscribe(&self, user: UserId) -> broadcast::Receiver<Arc<ServerEvent>> {
        let mut map = self.channels.lock().expect("hub lock poisoned");
        map.entry(user)
            .or_insert_with(|| broadcast::channel(USER_CHANNEL_CAPACITY).0)
            .subscribe()
    }

    pub fn dispatch(&self, msg: &BusMessage) {
        let event = Arc::new(msg.event.clone());
        let mut map = self.channels.lock().expect("hub lock poisoned");
        for user in &msg.users {
            if let Some(tx) = map.get(user) {
                if tx.send(event.clone()).is_err() {
                    // No live receivers: forget the channel.
                    map.remove(user);
                }
            }
        }
    }
}

#[derive(Clone)]
enum Bus {
    Local,
    Postgres(PgPool),
}

/// Publishing side used by handlers, and subscription side used by the
/// WebSocket handler.
#[derive(Clone)]
pub struct Events {
    hub: Arc<Hub>,
    bus: Bus,
    slots: Arc<Mutex<HashMap<UserId, usize>>>,
}

/// A reserved WebSocket slot; released on drop.
pub struct SlotGuard {
    slots: Arc<Mutex<HashMap<UserId, usize>>>,
    user: UserId,
}

impl fmt::Debug for SlotGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SlotGuard")
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut map = self.slots.lock().expect("slots lock poisoned");
        if let Some(n) = map.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.user);
            }
        }
    }
}

impl fmt::Debug for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.bus {
            Bus::Local => "local",
            Bus::Postgres(_) => "postgres",
        };
        f.debug_struct("Events").field("bus", &kind).finish()
    }
}

impl Events {
    /// Create the event system. For the PostgreSQL bus this starts the
    /// LISTEN task and returns once it is subscribed.
    pub async fn start(kind: EventBusKind, pool: &PgPool) -> anyhow::Result<Self> {
        let hub = Arc::new(Hub::default());
        let bus = match kind {
            EventBusKind::Local => Bus::Local,
            EventBusKind::Postgres => {
                let mut listener = PgListener::connect_with(pool).await?;
                listener.listen(CHANNEL).await?;
                tokio::spawn(listen_loop(listener, hub.clone()));
                Bus::Postgres(pool.clone())
            }
        };
        Ok(Self {
            hub,
            bus,
            slots: Arc::default(),
        })
    }

    /// Publisher without a local listener (admin CLI): events go over the
    /// PostgreSQL bus to the running server replicas.
    pub fn publisher(pool: &PgPool) -> Self {
        Self {
            hub: Arc::new(Hub::default()),
            bus: Bus::Postgres(pool.clone()),
            slots: Arc::default(),
        }
    }

    /// Atomically reserve one of `max` WebSocket slots of `user` on this
    /// replica (before the upgrade, so concurrent upgrades cannot overshoot).
    pub fn try_reserve_slot(&self, user: UserId, max: usize) -> Option<SlotGuard> {
        let mut map = self.slots.lock().expect("slots lock poisoned");
        let n = map.entry(user).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(SlotGuard {
            slots: self.slots.clone(),
            user,
        })
    }

    pub fn subscribe(&self, user: UserId) -> broadcast::Receiver<Arc<ServerEvent>> {
        self.hub.subscribe(user)
    }

    /// Publish to `users`. Call after the corresponding transaction committed.
    /// Never fails: events are hints, errors are logged.
    pub async fn publish(&self, users: Vec<UserId>, event: ServerEvent) {
        if users.is_empty() {
            return;
        }
        let msg = BusMessage { users, event };
        metrics::counter!("cc_events_published_total").increment(1);
        match &self.bus {
            Bus::Local => self.hub.dispatch(&msg),
            Bus::Postgres(pool) => {
                let payload = match serde_json::to_string(&msg) {
                    Ok(p) => p,
                    Err(err) => {
                        tracing::error!(failure = ?err.classify(), "cannot serialize event");
                        return;
                    }
                };
                if let Err(err) = sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(CHANNEL)
                    .bind(payload)
                    .execute(pool)
                    .await
                {
                    tracing::warn!(
                        failure = crate::error::database_error_kind(&err),
                        "failed to publish event"
                    );
                }
            }
        }
    }

    pub async fn publish_user(&self, user: UserId, event: ServerEvent) {
        self.publish(vec![user], event).await;
    }

    /// Publish to every current member of `vault_id`.
    pub async fn publish_vault(&self, db: &PgPool, vault_id: VaultId, event: ServerEvent) {
        let members: Result<Vec<Uuid>, _> = sqlx::query_scalar(
            "SELECT user_id FROM vault_members WHERE vault_id = $1 AND revoked_at IS NULL",
        )
        .bind(Uuid::from(vault_id))
        .fetch_all(db)
        .await;
        match members {
            Ok(users) => {
                self.publish(users.into_iter().map(UserId::from).collect(), event)
                    .await
            }
            Err(err) => tracing::warn!(
                failure = crate::error::database_error_kind(&err),
                "cannot resolve vault members for event"
            ),
        }
    }
}

async fn listen_loop(mut listener: PgListener, hub: Arc<Hub>) {
    loop {
        match listener.recv().await {
            Ok(notification) => match serde_json::from_str::<BusMessage>(notification.payload()) {
                Ok(msg) => hub.dispatch(&msg),
                Err(err) => {
                    tracing::warn!(failure = ?err.classify(), "ignoring malformed event notification")
                }
            },
            Err(err) => {
                // recv() reconnects on the next call; back off a little.
                tracing::warn!(
                    failure = crate::error::database_error_kind(&err),
                    "event listener error; reconnecting"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_protocol::DeviceId;

    #[tokio::test]
    async fn hub_routes_by_user() {
        let hub = Hub::default();
        let a = UserId::new();
        let b = UserId::new();
        let mut ra = hub.subscribe(a);
        let mut rb = hub.subscribe(b);
        let ev = ServerEvent::DeviceAdded {
            device_id: DeviceId::new(),
        };
        hub.dispatch(&BusMessage {
            users: vec![a],
            event: ev.clone(),
        });
        assert_eq!(*ra.recv().await.unwrap(), ev);
        assert!(rb.try_recv().is_err());
    }

    #[test]
    fn bus_message_roundtrip() {
        let msg = BusMessage {
            users: vec![UserId::new()],
            event: ServerEvent::VaultChanged {
                vault_id: VaultId::new(),
                latest_sequence: 7,
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.len() < 8000);
        let back: BusMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event, msg.event);
    }
}
