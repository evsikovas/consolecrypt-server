# Protocol and encrypted model changes

## Unreleased

- Protocol 1.8 (2026-10-22, server 0.2.0, additive): enterprise sign-in mode
  (`cc_protocol::enterprise_auth`). Servers in the default `standard` mode
  behave as before; older clients keep working against them unchanged.
  - `ServerInfo.capabilities.auth` (`AuthCapability { mode, provider,
    display_name }`): `mode` = `standard` | `enterprise`, `provider` =
    `oidc` | `ldap` (enterprise only), optional `display_name` for the
    sign-in button. Absent on older servers = `standard`. Unknown future
    values decode as `unknown` (ask the user to update the app).
    `registration_open` is meaningless in enterprise mode.
  - OIDC (system browser, PKCE S256 on both legs):
    `GET /v1/auth/oidc/start?redirect_uri&code_challenge[&code_challenge_method=S256]&state&device_id[&login_hint]`
    (`OidcStartQuery`, `OidcStartQuery::to_url`) → redirect to the IdP →
    `GET /v1/auth/oidc/callback` (server-side) → redirect to the app's
    `redirect_uri` with `login_code` + `state` or `error` +
    `error_description` + `state` (`OidcAppCallback`). Allowed app redirect
    URIs only: `http://127.0.0.1:{port}/auth/callback`,
    `http://[::1]:{port}/auth/callback`, `consolecrypt://auth/callback`
    (`is_allowed_app_redirect_uri`). `POST /v1/auth/oidc/exchange`
    `OidcExchangeRequest { login_code, code_verifier, device, device_proof? }`
    → `AuthResponse`. The `login_code` is single use, valid
    `OIDC_LOGIN_CODE_TTL_SECONDS` (60 s) and bound to the `code_challenge`
    and `device_id`; a flow lives `OIDC_FLOW_TTL_SECONDS` (600 s).
  - LDAP / Active Directory: `POST /v1/auth/ldap/login`
    `LdapLoginRequest { login, password, device, device_proof? }` →
    `AuthResponse`; unknown login and wrong password are indistinguishable
    (`401 invalid_credentials`).
  - Device rules are those of password login: `device_proof` is required for
    an already registered device; a new device is untrusted and subject to
    device protection (1.7).
  - New error codes: `enterprise_auth_required` (403; register, password
    login, password reset/change and email verification on an enterprise
    server — the message asks older clients to update the app, which fall
    back to `forbidden`), `identity_conflict` (409), `domain_not_allowed`
    (403), `group_required` (403), `mfa_required` (403), `idp_unavailable`
    (503, retryable), `account_disabled` (403; also from
    `POST /v1/auth/refresh` when the periodic re-check finds the user
    disabled, deleted or outside the required group — the session family is
    revoked).
  - New limits: `MAX_OIDC_STATE_LEN` (512), `MAX_ENTERPRISE_LOGIN_LEN` (256).

- Protocol 1.7 (2026-10-21, server 0.1.16, additive): new-device protection
  (security audit S1), active only while the server advertises
  `capabilities.device_protection` in `/v1/meta` (new `ServerInfo.capabilities`
  object, `CC_DEVICE_PROTECTION_ENABLED`, default off):
  - `ServerEvent::DeviceRegistered { device_id, name, platform, created_at }`,
    sent to the account in addition to `device_added` when a login creates a
    device. Older clients ignore it (`Unknown`).
  - `DeviceInfo.trusted` (live device envelope for any vault) and
    `DeviceInfo.quarantine_until`.
  - Error codes `device_in_quarantine` (403, `details.until`) and
    `envelope_rate_limited` (429, `retry_after_seconds` and `Retry-After`).
    Older clients cannot decode the new codes and fall back to the HTTP status
    (`forbidden` / `rate_limited`).
  - Quarantine: a device younger than the quarantine may revoke only itself
    and untrusted devices; its `logout {all_sessions}` and password change
    keep trusted devices signed in. Such a logout answers `200
    LogoutResponse { sessions_revoked, trusted_devices_kept, quarantine_until }`
    instead of `204`. ADR-0004 amendment: the rule "any active device may
    revoke any device" now has this exception; the device that registered the
    account never starts in quarantine, and approval by a trusted device past
    quarantine ends it early. Unlocking with the vault passphrase does not;
    the Recovery Key does not either (open question, safe default).
  - Unlock material (`GET /v1/recovery/vault/envelope`,
    `GET /v1/vaults/{id}/envelopes` for a device not trusted for the vault) is
    metered per account and device; repeating the same vault for the same
    device within the hour is free.
  - `POST /v1/devices/deny { token }` (unauthenticated) → `DenyDeviceResponse`:
    the single-use `ccd_…` "This wasn't me" token of a security mail revokes
    only its device (or, from the password-reset mail, untrusted devices that
    signed in since), never a trusted one (`403 forbidden`,
    `details.reason = "device_trusted"`).
  - Independent of the flag: a password reset invalidates all other reset and
    email-verification tokens; a password change invalidates pending reset
    tokens. With the flag, a reset also revokes devices that never held a
    device envelope (`devices.first_trusted_at IS NULL`).

- Protocol 1.6 (2026-10-21, server 0.1.15, additive): new selective-sharing
  kind `db_connection` (`SharedItemKind::DbConnection`, signed domain byte 6)
  for encrypted database connection projections. The server advertises it as
  `supports_db_connections` in `/v1/shares/capabilities` only when
  `CC_SHARED_DB_CONNECTIONS_ENABLED=true` (requires object sharing and strict
  request proofs). `GET /v1/shares` returns `db_connection` items only with an
  explicit `include_db_connections=true`, so 1.5 clients never receive a kind
  they cannot decode. Publication of the kind is rejected while the flag is
  off; turning it off hides existing items without deleting ciphertext. The
  server never sees connection parameters or credentials and has no storage
  migration for this kind.

- Client Dev (2026-10-03, client-only encrypted payloads): add the independent
  `rdp_host` object kind under the Inventory KEK, with host identity/group/tags,
  an explicit password-credential reference, domain and desktop dimensions.
  It is deliberately not a new optional flag on `host`: older clients skip
  unknown encrypted object kinds and retain their ciphertext, instead of
  treating an RDP endpoint as SSH or dropping its settings when re-saving.
  Existing SSH bytes, server DTOs, encryption format and wire version are
  unchanged. Clipboard/folder permissions and certificate decisions are local
  session state and never part of the synced object. RDP sharing is not enabled
  by this model addition.
