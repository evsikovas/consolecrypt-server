# Protocol and encrypted model changes

## Unreleased

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
