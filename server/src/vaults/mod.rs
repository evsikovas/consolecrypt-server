// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Vault metadata, membership and key envelopes (`/v1/vaults/*`).
//!
//! The server stores no VRK and no plaintext vault metadata (even the vault
//! name is an encrypted object inside the vault).

pub mod access;
pub mod envelopes;
pub mod handlers;

pub use access::VaultAccess;
