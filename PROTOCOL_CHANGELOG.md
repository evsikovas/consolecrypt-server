# Protocol and encrypted model changes

## Unreleased

- Protocol 1.8 (2026-10-22, server 0.1.17, additive): owner-only delete of
  shared items with a restore window, and recipients leaving a share
  (internal security audit, low). Advertised in `/v1/meta` as
  `capabilities.share_leave` and `capabilities.share_restore` whenever object
  sharing is enabled; clients hide the actions otherwise.
  - Only the owner account may append a `Delete` tombstone. An editor gets
    `403 owner_only` (new `ErrorCode::OwnerOnly`); older clients cannot decode
    the code and fall back to the HTTP status (`forbidden`). Edits by editors
    are unchanged.
  - On an owner delete the server keeps the last content revision
    (ciphertext and per-device envelopes, never plaintext) for
    `sharing::RESTORE_WINDOW_DAYS` = 30. `GET /v1/shares/deleted?after=&limit=`
    (owner devices that are members) → `DeletedShareListPage` of
    `DeletedSharedItem { state, last_revision, deleted_at, restorable_until,
    departed_user_ids }`. A tombstone is never resurrected (clients refuse
    revisions after it): the owner verifies `last_revision` against the
    tombstone's `previous_revision_hash`, opens it and republishes it as a new
    item with `CreateShareRequest.restored_from` (optional, omitted when
    `None`). The server checks ownership, kind, the window and that no
    departed account is included (`403`), then drops the retained content;
    a second restore answers `410 gone`. Maintenance drops retained content
    after the window; the signed tombstone stays.
  - Quota: the 1000-item limit counts live and still restorable items; expired
    tombstones no longer count (hard cap of 10 000 rows per owner).
  - `POST /v1/shares/{id}/leave` → `204` for a recipient account (the owner
    gets `403`, a non-member `404`): all devices of that account lose server
    access at once. The owner's `ShareListPage` carries
    `departures: [{ share_id, user_id }]` (omitted when empty, never shown to
    other recipients). The departure persists until the owner's next signed
    manifest drops the account, or adds a device of it that the previous
    manifest did not contain (an explicit new invitation); a manifest that
    merely keeps the old devices does not let them back in. A departed account
    has no enrollment authority on that item.
  - Migration `0009_share_owner_delete`: `shared_items.deleted_at`,
    `shared_items.restore_revision`, `shared_item_departures`.
  - `POST /v1/shares/recipients/lookup` with body
    `RecipientLookupRequest { email }` (unknown fields rejected) answers the
    same `SharingRecipient` as before, with the same authentication, request
    proof, verified-email requirement and per-device rate limit, so the
    address no longer appears in URLs or reverse-proxy access logs.
    Advertised as `capabilities.recipient_lookup_post`. **Deprecated:**
    `GET /v1/shares/recipients?email=` stays only for older clients; new
    clients use it only when the capability is absent. The server's own
    access log records the route template only (never query strings or
    bodies).

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
