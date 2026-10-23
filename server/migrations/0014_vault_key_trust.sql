-- Vault key trust (protocol 1.11, security audit 2026-10-21, finding H2).
-- Additive: older clients keep using v1 approvals and never touch these.
--
-- 1. Approval intent: the trusted device that announced it is approving a
--    pending request. The new device derives the mutual pairing code v2 from
--    its keys (returned as `DeviceTrustRequest.approver`).
ALTER TABLE device_requests
    ADD COLUMN intent_device_id uuid REFERENCES devices (id) ON DELETE SET NULL;
ALTER TABLE device_requests ADD COLUMN intent_at timestamptz;

-- 2. Approval v2 as signed by the approver: per vault the key commitment and
--    the SHA-256 of the device envelope sealed for the new device. Kept for
--    the approved device (`VaultRecoveryMaterial.device_approval`). Opaque to
--    the server apart from the checks done on approval.
CREATE TABLE device_approvals_v2 (
    request_id         uuid        PRIMARY KEY REFERENCES device_requests (id) ON DELETE CASCADE,
    device_id          uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    approver_device_id uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    issued_at          bigint      NOT NULL,
    -- [{vault_id, commitment, envelope_sha256}] exactly as signed (base64url).
    vault_commitments  jsonb       NOT NULL,
    signature          bytea       NOT NULL CHECK (length(signature) = 64),
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_approvals_v2_device_idx ON device_approvals_v2 (device_id, created_at DESC);

-- 3. Signed key-commitment records: one per (vault, device). Not secret;
--    they only let devices of the account notice a different vault key.
CREATE TABLE vault_key_commitments (
    vault_id   uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    device_id  uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    commitment bytea       NOT NULL CHECK (length(commitment) = 32),
    issued_at  bigint      NOT NULL,
    signature  bytea       NOT NULL CHECK (length(signature) = 64),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, device_id)
);
