//! Quotas and request limits (protocol 1.11, server 0.2.2): the values a
//! server puts into [`crate::ApiError::details`] when it refuses a request
//! because of a quota or a rate limit. Purely additive: no new error codes.
//!
//! * `429 rate_limited` carries `retry_after_seconds` (and the `Retry-After`
//!   header) plus `details.limit` = one of [`limit`] — which limit was hit, so
//!   the client can say what is throttled. Unknown values must be tolerated
//!   (show the generic "try again at …" message).
//! * Quotas answer without `Retry-After`: `413 payload_too_large` with
//!   `details.reason` = [`reason::VAULT_QUOTA`] (`limit_bytes`) or
//!   [`reason::OBJECT_LIMIT`] (`limit`), and `403 forbidden` at sign-in with
//!   [`reason::DEVICE_LIMIT`] (`limit`) or [`reason::DEVICE_DAILY_LIMIT`]
//!   (`limit`, `until`).

/// Key of the limit name in `details` of `429 rate_limited`.
pub const DETAILS_LIMIT: &str = "limit";
/// Key of the quota reason in `details` of `413`/`403`.
pub const DETAILS_REASON: &str = "reason";

/// `details.reason` values of quota refusals.
pub mod reason {
    /// `413`: the vault's bytes (live ciphertext + tombstones) would exceed
    /// `details.limit_bytes`.
    pub const VAULT_QUOTA: &str = "vault_quota";
    /// `413`: the vault would hold more than `details.limit` objects (live
    /// objects and tombstones together). Deleting live objects is always
    /// accepted.
    pub const OBJECT_LIMIT: &str = "object_limit";
    /// `403` at sign-in: the account already has `details.limit` active
    /// devices; revoke one to sign in on a new device.
    pub const DEVICE_LIMIT: &str = "device_limit";
    /// `403` at sign-in: more than `details.limit` new devices in 24 hours;
    /// `details.until` (RFC 3339) is when the next one is accepted.
    pub const DEVICE_DAILY_LIMIT: &str = "device_daily_limit";
}

/// `details.limit` values of `429 rate_limited`.
pub mod limit {
    /// Pushes per device.
    pub const PUSH_DEVICE: &str = "push_device";
    /// Pushes per account.
    pub const PUSH_ACCOUNT: &str = "push_account";
    /// Mutations in pushes per account.
    pub const MUTATIONS_ACCOUNT: &str = "mutations_account";
    /// Deletes of objects the server never had, per account.
    pub const UNKNOWN_DELETE_ACCOUNT: &str = "unknown_delete_account";
    /// Creating shared items.
    pub const SHARE_WRITE_ACCOUNT: &str = "share_write_account";
    /// Shared item revisions, access rotations and shared notes.
    pub const SHARE_REVISION_ACCOUNT: &str = "share_revision_account";
    /// Looking up sharing recipients by e-mail.
    pub const RECIPIENT_LOOKUP_ACCOUNT: &str = "recipient_lookup_account";
    /// Own-device enrollment: grants, requests, challenges, responses.
    pub const ENROLLMENT_ACCOUNT: &str = "enrollment_account";
    /// `POST /v1/devices` per device.
    pub const TRUST_REQUEST_DEVICE: &str = "trust_request_device";
    /// `POST /v1/devices` per account.
    pub const TRUST_REQUEST_ACCOUNT: &str = "trust_request_account";
    /// Key verification sessions.
    pub const VERIFICATION_ACCOUNT: &str = "verification_account";
    /// Password change, recovery kit re-issue, envelope replacement.
    pub const ACCOUNT_SECURITY: &str = "account_security";
    /// WebSocket connections per account (new connections per minute).
    pub const WS_CONNECT_ACCOUNT: &str = "ws_connect_account";
    /// Concurrent WebSocket connections per account on one server replica.
    pub const WS_CONNECTIONS: &str = "ws_connections";
    /// Public authentication endpoints per client address.
    pub const AUTH_IP: &str = "auth_ip";
    /// Failed sign-ins per e-mail and client network.
    pub const LOGIN_EMAIL: &str = "login_email";
    /// Failed sign-ins per e-mail from all networks.
    pub const LOGIN_EMAIL_TOTAL: &str = "login_email_total";
    /// Password reset / account recovery requests per e-mail and network.
    pub const RECOVERY_EMAIL: &str = "recovery_email";
    /// Vault access key attempts and similar proofs per device.
    pub const PROOF_DEVICE: &str = "proof_device";
    /// Reads (pull, lists) per device on one server replica.
    pub const READ_DEVICE: &str = "read_device";
}
