-- ADR-0009 owner-online enrollment. All documents contain public signed metadata
-- and opaque possession challenges only; no private keys, DEKs or plaintext.
CREATE TABLE shared_enrollment_grants (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    grant_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state_hash bytea NOT NULL CHECK (length(state_hash) = 32),
    access_manifest_hash bytea NOT NULL CHECK (length(access_manifest_hash) = 32),
    not_before bigint NOT NULL,
    anchor_user_id uuid NOT NULL,
    anchor_device_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    expires_at bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (share_id, grant_id)
);
CREATE INDEX shared_enrollment_grant_anchor_idx
    ON shared_enrollment_grants (share_id, anchor_user_id, anchor_device_id, grant_id);

CREATE TABLE shared_enrollment_grant_states (
    share_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    state_hash bytea NOT NULL CHECK (length(state_hash) = 32),
    document jsonb NOT NULL,
    PRIMARY KEY (share_id, grant_id, revision),
    FOREIGN KEY (share_id, grant_id)
        REFERENCES shared_enrollment_grants (share_id, grant_id) ON DELETE CASCADE
);

CREATE TABLE shared_enrollment_requests (
    share_id uuid NOT NULL,
    request_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    grant_state_hash bytea NOT NULL CHECK (length(grant_state_hash) = 32),
    request_hash bytea NOT NULL CHECK (length(request_hash) = 32),
    nonce bytea NOT NULL CHECK (length(nonce) = 32),
    target_user_id uuid NOT NULL,
    target_device_id uuid NOT NULL,
    expires_at bigint NOT NULL,
    accepted boolean NOT NULL DEFAULT false,
    document jsonb NOT NULL,
    PRIMARY KEY (share_id, request_id),
    UNIQUE (share_id, grant_id, nonce),
    FOREIGN KEY (share_id, grant_id)
        REFERENCES shared_enrollment_grants (share_id, grant_id) ON DELETE CASCADE
);
CREATE INDEX shared_enrollment_request_pending_idx
    ON shared_enrollment_requests (share_id, grant_id, expires_at) WHERE NOT accepted;

-- Keep identifiers/reuse fingerprints across replacements without exposing old
-- challenge ciphertext. An accepted request's current signed transcript is immutable.
CREATE TABLE shared_enrollment_challenges (
    share_id uuid NOT NULL,
    request_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    challenge_id uuid NOT NULL,
    ephemeral_public_key bytea NOT NULL CHECK (length(ephemeral_public_key) = 32),
    nonce bytea NOT NULL CHECK (length(nonce) = 24),
    ciphertext_hash bytea NOT NULL CHECK (length(ciphertext_hash) = 32),
    PRIMARY KEY (share_id, request_id, generation),
    UNIQUE (share_id, request_id, challenge_id),
    UNIQUE (share_id, request_id, ephemeral_public_key),
    UNIQUE (share_id, request_id, nonce),
    UNIQUE (share_id, request_id, ciphertext_hash),
    FOREIGN KEY (share_id, request_id)
        REFERENCES shared_enrollment_requests (share_id, request_id) ON DELETE CASCADE
);
