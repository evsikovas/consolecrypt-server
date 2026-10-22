// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Teams (protocol 1.9): team vaults, invitations, the signed membership
//! log, user envelopes and key rotation.

pub mod handlers;
pub mod log;

pub use handlers::routes;
