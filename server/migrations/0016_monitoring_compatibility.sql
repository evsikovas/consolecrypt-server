-- Compatibility metadata only. No catalog plaintext or key material.
-- Account scope is explicit: ALL of an opted-in owner's personal vaults.
CREATE TABLE account_monitoring_compatibility (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version integer NOT NULL DEFAULT 1 CHECK (version = 1),
    revision bigint NOT NULL CHECK (revision > 0),
    minimum_client_version text CHECK (length(minimum_client_version) BETWEEN 5 AND 64),
    quarantined boolean NOT NULL DEFAULT false,
    enabled_by_device_id uuid REFERENCES devices(id),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (quarantined OR minimum_client_version IS NOT NULL)
);
-- No per-request path/URL/secret payload. Highest minimum is retained on restore.
