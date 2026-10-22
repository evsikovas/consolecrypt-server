# Protocol and encrypted model changes

## Unreleased

- Shared notes (additive; protocol minor number assigned at merge after 1.8
  enterprise-auth and 1.9 teams), advertised as `supports_notes_v1` in
  `GET /v1/shares/capabilities` (`CC_SHARED_NOTES_ENABLED`, default off):
  - `cc_protocol::sharing_notes`: `SharedNotesKeySet` (owner-signed notes key
    of an access epoch, wrapped per member device like a revision DEK, labels
    `notes-key-set`, `notes-envelope-aad`, `notes-envelope-key`),
    `SharedNote` (XChaCha20-Poly1305 under HKDF(notes key, salt = note id,
    info = `note-key` ‖ epoch); AAD `note-aad`; the author device signs
    `note` over the payload hash, excluding the epoch so the owner can rekey).
  - `GET /v1/shares/{id}/notes`, `PUT /v1/shares/{id}/notes/keys` (owner
    device, current epoch, envelopes exactly for the member devices, never
    replaced), `PUT|DELETE /v1/shares/{id}/notes/{note_id}` (any member writes
    its own notes, revision + 1, current epoch; owner may delete any),
    `POST /v1/shares/{id}/notes/rekey` (owner device moves notes of earlier
    epochs into the current one, keeping authorship and signatures).
  - Limits: 500 notes per share, 288 KiB + 16 ciphertext per note, 100 notes
    per rekey request. Migration `0011_share_notes`.

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
