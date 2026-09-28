-- ConsoleCrypt server schema v1.
--
-- Zero-knowledge: nothing in this schema can decrypt vault data. Vault objects
-- and key envelopes are opaque ciphertext; tokens are stored only as SHA-256
-- hashes; account passwords only as Argon2id PHC strings.

-- ---------------------------------------------------------------- accounts --

CREATE TABLE users (
    id                  uuid        PRIMARY KEY,
    email               text        NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    password_hash       text        NOT NULL,
    status              text        NOT NULL DEFAULT 'active'
                                    CHECK (status IN ('active', 'disabled')),
    email_verified_at   timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- Client-generated DeviceId; globally unique (ADR-0201).
CREATE TABLE devices (
    id                    uuid        PRIMARY KEY,
    user_id               uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name                  text        NOT NULL,
    platform              text        NOT NULL,
    encryption_public_key bytea       NOT NULL CHECK (length(encryption_public_key) = 32),
    signing_public_key    bytea       NOT NULL CHECK (length(signing_public_key) = 32),
    client_version        text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz,
    revoked_at            timestamptz,
    revoke_reason         text
);
CREATE INDEX devices_user_idx ON devices (user_id);

-- One session = one refresh-token family bound to one device.
CREATE TABLE sessions (
    id                uuid        PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id         uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    access_token_hash bytea       NOT NULL UNIQUE CHECK (length(access_token_hash) = 32),
    access_expires_at timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_refreshed_at timestamptz,
    revoked_at        timestamptz,
    revoke_reason     text
);
CREATE INDEX sessions_user_live_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_device_live_idx ON sessions (device_id) WHERE revoked_at IS NULL;

-- Every refresh token ever issued for a session; a used token presented again
-- means the family leaked (reuse detection).
CREATE TABLE refresh_tokens (
    token_hash bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    session_id uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);

-- Single-use account tokens (password reset, email verification).
CREATE TABLE account_tokens (
    token_hash bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    text        NOT NULL CHECK (purpose IN ('password_reset', 'email_verify')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX account_tokens_user_idx ON account_tokens (user_id, purpose);

-- ------------------------------------------------------------------ vaults --

-- Client-generated VaultId (bound into AEAD associated data by clients).
CREATE TABLE vaults (
    id                    uuid        PRIMARY KEY,
    owner_user_id         uuid        NOT NULL REFERENCES users (id),
    state                 text        NOT NULL DEFAULT 'active'
                                      CHECK (state IN ('active', 'pending_deletion', 'deleted')),
    -- SHA-256(vault access key). One-way from VRK; cannot decrypt anything.
    access_key_verifier   bytea       NOT NULL CHECK (length(access_key_verifier) = 32),
    created_by_device_id  uuid        REFERENCES devices (id) ON DELETE SET NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz,
    deletion_scheduled_at timestamptz
);
CREATE INDEX vaults_owner_idx ON vaults (owner_user_id);

-- Team Vault foundation: membership is per user; MVP has only the owner.
CREATE TABLE vault_members (
    vault_id   uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('owner', 'admin', 'editor', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX vault_members_user_live_idx ON vault_members (user_id) WHERE revoked_at IS NULL;

-- Per-vault monotonic, gap-free sequence. Its row lock serialises pushes.
CREATE TABLE vault_sequences (
    vault_id      uuid   PRIMARY KEY REFERENCES vaults (id) ON DELETE CASCADE,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0)
);

-- VRK encrypted for a recipient. Opaque to the server.
CREATE TABLE vault_key_envelopes (
    id                   uuid        PRIMARY KEY,
    vault_id             uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    recipient_type       text        NOT NULL
                                     CHECK (recipient_type IN ('password', 'recovery', 'device', 'user', 'organization_future')),
    recipient_id         uuid,
    kind                 text        NOT NULL,
    algorithm            text        NOT NULL,
    -- EnvelopeMetadata JSON: algorithm, KDF params + salt, ephemeral public key. Not secret.
    metadata             jsonb       NOT NULL,
    ciphertext           bytea       NOT NULL,
    nonce                bytea       NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    created_by_device_id uuid        REFERENCES devices (id) ON DELETE SET NULL,
    revoked_at           timestamptz,
    revoke_reason        text,
    CHECK ((recipient_type IN ('device', 'user')) = (recipient_id IS NOT NULL))
);
-- At most one live envelope per (vault, recipient).
CREATE UNIQUE INDEX vault_key_envelopes_live_key
    ON vault_key_envelopes (vault_id, recipient_type,
                            COALESCE(recipient_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE revoked_at IS NULL;
CREATE INDEX vault_key_envelopes_device_live_idx
    ON vault_key_envelopes (recipient_id)
    WHERE revoked_at IS NULL AND recipient_type = 'device';

-- -------------------------------------------------------------------- sync --

-- Latest state of every object (no history in v1). Tombstone = deleted + NULL body.
CREATE TABLE vault_objects (
    vault_id          uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    object_id         uuid        NOT NULL,
    revision          bigint      NOT NULL CHECK (revision > 0),
    sequence          bigint      NOT NULL CHECK (sequence > 0),
    deleted           boolean     NOT NULL DEFAULT false,
    format            smallint,
    ciphertext        bytea,
    nonce             bytea,
    wrapped_dek       bytea,
    wrapped_dek_nonce bytea,
    writer_device_id  uuid        NOT NULL REFERENCES devices (id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, object_id),
    CHECK (
        (deleted AND format IS NULL AND ciphertext IS NULL AND nonce IS NULL
                 AND wrapped_dek IS NULL AND wrapped_dek_nonce IS NULL)
        OR
        (NOT deleted AND format IS NOT NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL
                     AND wrapped_dek IS NOT NULL AND wrapped_dek_nonce IS NOT NULL)
    )
);
CREATE UNIQUE INDEX vault_objects_sequence_key ON vault_objects (vault_id, sequence);
CREATE INDEX vault_objects_live_sequence_idx ON vault_objects (vault_id, sequence) WHERE NOT deleted;

-- Idempotency log of accepted mutations.
CREATE TABLE sync_mutations (
    mutation_id     uuid        PRIMARY KEY,
    vault_id        uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    object_id       uuid        NOT NULL,
    device_id       uuid        NOT NULL,
    result_revision bigint      NOT NULL,
    result_sequence bigint      NOT NULL,
    accepted_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sync_mutations_accepted_idx ON sync_mutations (accepted_at);

-- ------------------------------------------------------------ device trust --

CREATE TABLE device_requests (
    id                    uuid        PRIMARY KEY,
    user_id               uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id             uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    status                text        NOT NULL
                                      CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    decided_at            timestamptz,
    approved_by_device_id uuid        REFERENCES devices (id) ON DELETE SET NULL
);
CREATE INDEX device_requests_user_pending_idx ON device_requests (user_id) WHERE status = 'pending';
CREATE INDEX device_requests_device_idx ON device_requests (device_id);

CREATE TABLE device_request_vaults (
    request_id uuid NOT NULL REFERENCES device_requests (id) ON DELETE CASCADE,
    vault_id   uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    PRIMARY KEY (request_id, vault_id)
);

-- ------------------------------------------------------------------- audit --

-- Metadata only: never content, tokens, passwords, envelopes or ciphertext.
-- No foreign keys so audit history survives deletions.
CREATE TABLE audit_events (
    id          uuid        PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_type  text        NOT NULL,
    user_id     uuid,
    device_id   uuid,
    target_id   uuid,
    request_id  uuid,
    ip_address  text,
    metadata    jsonb       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_user_idx ON audit_events (user_id, occurred_at DESC);
CREATE INDEX audit_events_time_idx ON audit_events (occurred_at);
