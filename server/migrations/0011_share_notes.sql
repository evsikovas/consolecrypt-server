-- share_notes_v1: notes travelling with a shared object. 0009/0010 are claimed
-- by parallel branches (teams, owner delete); renumber at merge if needed.
-- Ciphertext only: the notes key of an epoch is wrapped per member device and
-- signed by the owner device; notes are signed by their author device.

-- One owner-signed key set per access epoch.
CREATE TABLE shared_note_keys (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    access_epoch bigint NOT NULL CHECK (access_epoch > 0),
    key_set jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (share_id, access_epoch)
);

CREATE TABLE shared_notes (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    note_id uuid NOT NULL,
    author_user_id uuid NOT NULL REFERENCES users (id),
    author_device_id uuid NOT NULL REFERENCES devices (id),
    revision bigint NOT NULL CHECK (revision > 0),
    access_epoch bigint NOT NULL CHECK (access_epoch > 0),
    nonce bytea NOT NULL CHECK (length(nonce) = 24),
    ciphertext bytea NOT NULL,
    payload_hash bytea NOT NULL CHECK (length(payload_hash) = 32),
    signature bytea NOT NULL CHECK (length(signature) = 64),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (share_id, note_id)
);
CREATE INDEX shared_notes_epoch_idx ON shared_notes (share_id, access_epoch);
