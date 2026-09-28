-- Single-use nonces of device login proofs (protocol 1.4, ADR-0006). A row
-- lives until its proof could no longer pass the clock-skew check; the
-- maintenance pass deletes expired rows.
CREATE TABLE device_login_nonces (
    device_id  uuid        NOT NULL,
    nonce      bytea       NOT NULL CHECK (length(nonce) = 32),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, nonce)
);
CREATE INDEX device_login_nonces_expiry_idx ON device_login_nonces (expires_at);
