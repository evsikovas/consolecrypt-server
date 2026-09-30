-- Experimental object_sharing_v1. 0005 is reserved for ADR-0007 vault chains.
-- Independent from personal vault membership, access keys and recovery.
CREATE TABLE sharing_instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    instance_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid()
);
INSERT INTO sharing_instance (singleton) VALUES (true);

CREATE TABLE shared_items (
    id uuid PRIMARY KEY,
    owner_user_id uuid NOT NULL REFERENCES users (id),
    owner_device_id uuid NOT NULL REFERENCES devices (id),
    revision bigint NOT NULL CHECK (revision > 0),
    access_epoch bigint NOT NULL CHECK (access_epoch > 0),
    manifest_revision bigint NOT NULL CHECK (manifest_revision > 0),
    manifest_hash bytea NOT NULL CHECK (length(manifest_hash) = 32),
    revision_hash bytea NOT NULL CHECK (length(revision_hash) = 32),
    deleted boolean NOT NULL DEFAULT false,
    -- Signed opaque wire documents, never plaintext / DEKs / personal VRKs.
    current_manifest jsonb NOT NULL,
    current_mutation jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shared_items_owner_idx ON shared_items (owner_user_id);

-- Keep signed public manifest history so recipients can verify chain links.
-- Ciphertext/envelope history is not exposed or retained here.
CREATE TABLE shared_manifests (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    manifest_revision bigint NOT NULL CHECK (manifest_revision > 0),
    manifest_hash bytea NOT NULL CHECK (length(manifest_hash) = 32),
    document jsonb NOT NULL,
    PRIMARY KEY (share_id, manifest_revision)
);

-- Current ACL is derived from the verified owner-signed manifest only.
CREATE TABLE shared_item_devices (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices (id),
    user_id uuid NOT NULL REFERENCES users (id),
    role text NOT NULL CHECK (role IN ('read', 'edit')),
    PRIMARY KEY (share_id, device_id)
);
CREATE INDEX shared_item_devices_user_idx ON shared_item_devices (user_id, device_id);

-- Signed headers prove revision continuity without releasing old ciphertext.
CREATE TABLE shared_revision_headers (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    mutation_id uuid NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (share_id, revision),
    UNIQUE (share_id, mutation_id)
);
