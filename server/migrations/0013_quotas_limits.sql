-- Quotas and request limits (security audit 2026-10-21, finding S2).

-- Token buckets shared by every replica (ADR-0201 amendment). Keys are
-- device/account ids or SHA-256-derived ids of an IP network or an e-mail
-- address (never the address itself). Rows not touched for a day are full
-- again and are deleted by the maintenance pass. UNLOGGED: no WAL and no
-- fsync per request (the check must stay within a few ms of the request);
-- after a database crash or a fail-over the buckets simply start full.
CREATE UNLOGGED TABLE rate_buckets (
    scope      text             NOT NULL,
    key        uuid             NOT NULL,
    tokens     double precision NOT NULL,
    updated_at timestamptz      NOT NULL,
    PRIMARY KEY (scope, key)
);
CREATE INDEX rate_buckets_updated_idx ON rate_buckets (updated_at);

-- Take p_costs[i] tokens from every bucket i, or none at all. Buckets refill
-- at p_rates[i] tokens per second up to p_caps[i]; time comes from the
-- database clock only. Returns (0, 0) when everything was taken, otherwise
-- the 1-based index of the first bucket that is short and by how much (the
-- caller turns that into Retry-After). Callers pass buckets in a stable order
-- so concurrent calls cannot deadlock.
CREATE FUNCTION cc_rate_take(p_scopes text[], p_keys uuid[], p_rates float8[],
                             p_caps float8[], p_costs float8[])
RETURNS TABLE (refused_index integer, shortfall float8)
LANGUAGE plpgsql AS $$
DECLARE
    n     integer := coalesce(array_length(p_scopes, 1), 0);
    have  float8[] := '{}';
    t     float8;
BEGIN
    FOR i IN 1..n LOOP
        INSERT INTO rate_buckets AS b (scope, key, tokens, updated_at)
        VALUES (p_scopes[i], p_keys[i], p_caps[i], now())
        ON CONFLICT (scope, key) DO UPDATE
           SET tokens = LEAST(p_caps[i],
                              b.tokens + p_rates[i] * GREATEST(0::float8,
                                  EXTRACT(EPOCH FROM (now() - b.updated_at))::float8)),
               updated_at = now()
        RETURNING b.tokens INTO t;
        have[i] := t;
    END LOOP;
    FOR i IN 1..n LOOP
        IF have[i] < p_costs[i] THEN
            refused_index := i;
            shortfall := p_costs[i] - have[i];
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;
    FOR i IN 1..n LOOP
        UPDATE rate_buckets SET tokens = have[i] - p_costs[i]
         WHERE scope = p_scopes[i] AND key = p_keys[i];
    END LOOP;
    refused_index := 0;
    shortfall := 0;
    RETURN NEXT;
END
$$;

-- Per-account overrides of limits and quotas (`consolecrypt-server admin
-- limits`). Keys are the configuration names without the CC_ / CC_LIMIT_
-- prefix in lower case, e.g. `push_account_rate` or `max_vault_objects`.
CREATE TABLE account_limits (
    user_id    uuid             NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key        text             NOT NULL CHECK (key ~ '^[a-z0-9_]{1,64}$'),
    value      double precision NOT NULL CHECK (value >= 0),
    updated_at timestamptz      NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);

-- Object counters for CC_MAX_VAULT_OBJECTS and the tombstone share of the
-- storage quota, maintained by the push transaction under the
-- vault_sequences row lock (like stored_bytes).
ALTER TABLE vault_sequences
    ADD COLUMN object_count    bigint NOT NULL DEFAULT 0 CHECK (object_count >= 0),
    ADD COLUMN tombstone_count bigint NOT NULL DEFAULT 0 CHECK (tombstone_count >= 0);

-- Backfill (one pass over vault_objects; may take a while on large servers).
UPDATE vault_sequences s
   SET object_count = c.objects, tombstone_count = c.tombstones
  FROM (SELECT vault_id, count(*) AS objects, count(*) FILTER (WHERE deleted) AS tombstones
          FROM vault_objects GROUP BY vault_id) c
 WHERE c.vault_id = s.vault_id;
