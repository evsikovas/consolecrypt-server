-- Enterprise sign-in (protocol 1.8, server 0.2.0): accounts authenticated by
-- an OIDC IdP or an LDAP / Active Directory directory instead of an account
-- password. Additive and forward-only: existing accounts, passwords and
-- sessions are untouched; with CC_AUTH_MODE=standard (default) nothing here
-- is used.

-- Accounts linked to an identity have no account password. Dropping NOT NULL
-- is a catalog-only change (no table rewrite).
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- External identity of an account: OIDC (iss, sub) or the directory's stable
-- id (objectGUID). The email is only an attribute: a changed email in the
-- directory does not break the link, and another account with the same email
-- is never taken over.
CREATE TABLE account_identities (
    account_id             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider               text        NOT NULL CHECK (provider IN ('oidc', 'ldap')),
    issuer                 text        NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject                text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024),
    -- Last email seen from the IdP/directory (attribute, not a key).
    email                  text        CHECK (email IS NULL OR length(email) <= 254),
    linked_at              timestamptz NOT NULL DEFAULT now(),
    last_login_at          timestamptz,
    -- Last successful re-check at the IdP/directory (ТР-6).
    checked_at             timestamptz NOT NULL DEFAULT now(),
    -- First failed re-check because the IdP/directory was unreachable since
    -- the last success (grace window); NULL when healthy.
    check_unavailable_since timestamptz,
    -- Upstream (IdP) refresh token, sealed with CC_OIDC_TOKEN_KEY_FILE
    -- (ChaCha20-Poly1305). Never vault data; never logged.
    upstream_refresh_token bytea       CHECK (upstream_refresh_token IS NULL
                                              OR length(upstream_refresh_token) <= 16384),
    PRIMARY KEY (provider, issuer, subject)
);
-- One identity per account and source.
CREATE UNIQUE INDEX account_identities_account_source_key
    ON account_identities (account_id, provider, issuer);
CREATE INDEX account_identities_checked_idx ON account_identities (checked_at);

-- Browser sign-ins in flight (/v1/auth/oidc/start → callback), 10 minutes.
-- Keyed by SHA-256 of the server's `state`; single use.
CREATE TABLE oidc_flows (
    state_hash         bytea       PRIMARY KEY CHECK (length(state_hash) = 32),
    nonce              text        NOT NULL CHECK (length(nonce) <= 128),
    -- Server-side PKCE verifier for the IdP leg (useless without the IdP's
    -- authorization code, which only reaches our callback).
    pkce_verifier      text        NOT NULL CHECK (length(pkce_verifier) <= 128),
    app_redirect_uri   text        NOT NULL CHECK (length(app_redirect_uri) <= 256),
    app_state          text        NOT NULL CHECK (length(app_state) <= 512),
    app_code_challenge text        NOT NULL CHECK (length(app_code_challenge) = 43),
    device_id          uuid        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL
);
CREATE INDEX oidc_flows_expiry_idx ON oidc_flows (expires_at);

-- Single-use login codes handed to the app (60 s), bound to the app's PKCE
-- challenge and device. SHA-256 only.
CREATE TABLE oidc_login_codes (
    code_hash      bytea       PRIMARY KEY CHECK (length(code_hash) = 32),
    user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_challenge text        NOT NULL CHECK (length(code_challenge) = 43),
    device_id      uuid        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);
CREATE INDEX oidc_login_codes_expiry_idx ON oidc_login_codes (expires_at);

-- Failed LDAP logins per normalised login, per directory user and per client
-- IP (fixed window, shared by all replicas): protects directory accounts
-- from being locked out through this server. Keys are SHA-256 digests.
CREATE TABLE ldap_login_failures (
    scope        text        NOT NULL CHECK (scope IN ('login', 'user', 'ip')),
    key          bytea       NOT NULL CHECK (length(key) = 32),
    window_start timestamptz NOT NULL,
    failures     integer     NOT NULL CHECK (failures >= 0),
    PRIMARY KEY (scope, key)
);
CREATE INDEX ldap_login_failures_window_idx ON ldap_login_failures (window_start);

-- Last check of the IdP/directory (startup validation, re-checks), shown by
-- `consolecrypt-server admin auth status`.
CREATE TABLE auth_provider_status (
    singleton  boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    provider   text        NOT NULL CHECK (provider IN ('oidc', 'ldap')),
    ok         boolean     NOT NULL,
    detail     text        NOT NULL CHECK (length(detail) <= 512),
    checked_at timestamptz NOT NULL DEFAULT now()
);
