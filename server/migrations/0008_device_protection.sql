-- New-device protection (security audit 2026-10-21, finding S1; protocol 1.7).
-- Additive: with CC_DEVICE_PROTECTION_ENABLED=false the server behaves as
-- before; the columns and tables are maintained anyway so turning the flag on
-- later starts from correct data.

-- First time the device held a device envelope (vault unlock + attest,
-- approval, or vault creation). NULL = never trusted: such devices are
-- revoked by a password reset.
ALTER TABLE devices ADD COLUMN first_trusted_at timestamptz;
-- Quarantine ended early (approved by a trusted device past quarantine) or
-- never started (the device that registered the account).
ALTER TABLE devices ADD COLUMN quarantine_lifted_at timestamptz;

-- Backfill from every device envelope ever stored, live or revoked.
UPDATE devices d
   SET first_trusted_at = t.first_at
  FROM (SELECT recipient_id, min(created_at) AS first_at
          FROM vault_key_envelopes
         WHERE recipient_type = 'device' AND recipient_id IS NOT NULL
         GROUP BY recipient_id) t
 WHERE d.id = t.recipient_id AND d.first_trusted_at IS NULL;

-- The device that registered an account (its oldest) never starts in
-- quarantine: it belongs to the owner by definition.
UPDATE devices d
   SET quarantine_lifted_at = d.created_at
 WHERE d.quarantine_lifted_at IS NULL
   AND d.id = (SELECT f.id FROM devices f WHERE f.user_id = d.user_id
                ORDER BY f.created_at, f.id LIMIT 1);

-- Single-use "This wasn't me" tokens from security mails (SHA-256 only).
-- `device_id` names the one device the token may revoke; a NULL device_id
-- (after a password reset) revokes the account's never-trusted devices
-- created since `created_at`.
CREATE TABLE device_deny_tokens (
    token_hash bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id  uuid        REFERENCES devices (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX device_deny_tokens_user_idx ON device_deny_tokens (user_id);
CREATE INDEX device_deny_tokens_expiry_idx ON device_deny_tokens (expires_at);

-- Fixed-window counters shared by all replicas: envelope hand-outs to
-- untrusted devices (per account / per device) and mail throttles.
CREATE TABLE rate_counters (
    scope        text        NOT NULL,
    key          uuid        NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL CHECK (count >= 0),
    PRIMARY KEY (scope, key, window_start)
);
CREATE INDEX rate_counters_window_idx ON rate_counters (window_start);

-- One row per (untrusted device, vault, hour) that received unlock material:
-- handing the same envelopes to the same device again in that hour reveals
-- nothing new and is not counted again (approval polling of 0.8.x clients).
CREATE TABLE envelope_issuances (
    device_id    uuid        NOT NULL,
    vault_id     uuid        NOT NULL,
    window_start timestamptz NOT NULL,
    PRIMARY KEY (device_id, vault_id, window_start)
);
CREATE INDEX envelope_issuances_window_idx ON envelope_issuances (window_start);
