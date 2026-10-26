-- Team key commitments (protocol 1.12, security review SEC-03b). Additive:
-- older clients never send or read them.
--
-- An owner or admin signs the key commitment (HKDF of the VRK) of a key
-- epoch with their per-team signing key from the membership log. Members
-- check the signature with that key, so the server cannot hand out a VRK
-- of its own, not even to a member opening the team for the first time.
-- One row per epoch; an admin may replace it (e.g. after the signer left).
CREATE TABLE team_key_commitments (
    vault_id       uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_epoch      integer     NOT NULL CHECK (key_epoch >= 0),
    commitment     bytea       NOT NULL CHECK (octet_length(commitment) = 32),
    signer_user_id uuid        NOT NULL,
    signature      bytea       NOT NULL CHECK (octet_length(signature) = 64),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, key_epoch)
);
