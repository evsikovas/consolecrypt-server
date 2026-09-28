// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>

//! Accounts and authentication (`/v1/auth/*`, `/v1/recovery/account/*`).
//!
//! The account password authenticates the account only; it never decrypts
//! anything and changing/resetting it never touches vault data (ADR-0004).

mod context;
pub mod handlers;
pub mod middleware;
pub mod sessions;

pub use context::{bearer_token, AuthContext};
