-- Teams (protocol 1.9). Additive: personal vaults are unchanged.
--
-- A team is a vault of kind 'team'. Members reach its VRK through a user
-- envelope (recipient_type 'user', recipient_id = user id) sealed to their
-- per-team identity key; membership changes form a hash-chained, signed log.

ALTER TABLE vaults ADD COLUMN kind text NOT NULL DEFAULT 'personal'
    CHECK (kind IN ('personal', 'team'));
-- Current team key epoch (0 = the VRK the team was created with).
ALTER TABLE vaults ADD COLUMN key_epoch integer NOT NULL DEFAULT 0 CHECK (key_epoch >= 0);
-- Last log entry: sequence number and SHA-256 hash (teams only).
ALTER TABLE vaults ADD COLUMN log_seq bigint;
ALTER TABLE vaults ADD COLUMN log_head bytea CHECK (log_head IS NULL OR length(log_head) = 32);
-- A member left or was removed since the last rotation.
ALTER TABLE vaults ADD COLUMN rotation_required boolean NOT NULL DEFAULT false;
CREATE INDEX vaults_kind_idx ON vaults (kind) WHERE kind = 'team';

-- The per-team public identity the log pinned for a member.
ALTER TABLE vault_members ADD COLUMN identity_encryption_key bytea
    CHECK (identity_encryption_key IS NULL OR length(identity_encryption_key) = 32);
ALTER TABLE vault_members ADD COLUMN identity_signing_key bytea
    CHECK (identity_signing_key IS NULL OR length(identity_signing_key) = 32);

-- User envelopes exist per key epoch.
ALTER TABLE vault_key_envelopes ADD COLUMN key_epoch integer NOT NULL DEFAULT 0;

-- The signed membership log (opaque JSON, verified on append).
CREATE TABLE team_log (
    vault_id   uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    seq        bigint      NOT NULL CHECK (seq >= 0),
    entry      jsonb       NOT NULL,
    hash       bytea       NOT NULL CHECK (length(hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, seq)
);

-- VRK of epoch - 1 sealed under the VRK of epoch (opaque).
CREATE TABLE team_key_chain (
    vault_id   uuid    NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_epoch  integer NOT NULL CHECK (key_epoch > 0),
    nonce      bytea   NOT NULL CHECK (length(nonce) = 24),
    ciphertext bytea   NOT NULL CHECK (length(ciphertext) = 48),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, key_epoch)
);

CREATE TABLE team_invitations (
    id                      uuid        PRIMARY KEY,
    vault_id                uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    inviter_user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    invitee_user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role                    text        NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
    note                    text,
    status                  text        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'accepted', 'completed', 'declined',
                                              'cancelled', 'expired')),
    identity_encryption_key bytea       CHECK (identity_encryption_key IS NULL
                                               OR length(identity_encryption_key) = 32),
    identity_signing_key    bytea       CHECK (identity_signing_key IS NULL
                                               OR length(identity_signing_key) = 32),
    created_at              timestamptz NOT NULL DEFAULT now(),
    expires_at              timestamptz NOT NULL,
    decided_at              timestamptz
);
CREATE INDEX team_invitations_invitee_idx ON team_invitations (invitee_user_id)
    WHERE status IN ('pending', 'accepted');
CREATE INDEX team_invitations_vault_idx ON team_invitations (vault_id, status);
-- One open invitation per invitee and team.
CREATE UNIQUE INDEX team_invitations_open_idx ON team_invitations (vault_id, invitee_user_id)
    WHERE status IN ('pending', 'accepted');
