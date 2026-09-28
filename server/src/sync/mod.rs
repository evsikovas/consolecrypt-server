// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Sync protocol v1 (`/v1/sync/*`, ADR-0003).
//!
//! * Per-vault monotonic, gap-free `sequence`, allocated under the row lock of
//!   `vault_sequences` inside the push transaction.
//! * Per-object `revision` with optimistic concurrency (`base_revision`).
//! * Idempotency by `mutation_id` (`sync_mutations`).
//! * The server stores and returns ciphertext; it never interprets it.

pub mod handlers;
