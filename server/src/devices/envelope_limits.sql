-- One accepted issuance contributes once to each physical bucket. During the
-- first UTC hour the account's hourly and daily windows start at the same
-- instant. They share a row, but still have separate limits and expiry times.
WITH boundaries AS (
    SELECT date_trunc('hour', $1::timestamptz, 'UTC') AS hour_start,
           date_trunc('day', $1::timestamptz, 'UTC') AS day_start
), limits(scope, key, window_start, span, max_count, label, priority) AS (
    SELECT rules.* FROM boundaries b CROSS JOIN LATERAL (VALUES
        ('envelopes_account', $2::uuid, b.hour_start, interval '1 hour', $4::bigint, 'account_hour', 1),
        ('envelopes_account', $2::uuid, b.day_start, interval '24 hours', $5::bigint, 'account_day', 2),
        ('envelopes_device', $3::uuid, b.hour_start, interval '1 hour', $6::bigint, 'device_hour', 3)
    ) AS rules
), bumped AS (
    INSERT INTO rate_counters AS c (scope, key, window_start, count)
    SELECT DISTINCT scope, key, window_start, 1 FROM limits WHERE max_count > 0
    -- Same lock order as existing replicas: account hour, account day, device.
    ORDER BY scope, key, window_start DESC
    ON CONFLICT (scope, key, window_start) DO UPDATE SET count = c.count + 1
    RETURNING scope, key, window_start, count
)
SELECT label, ceil(extract(epoch FROM (window_start + span - $1)))::int
FROM limits JOIN bumped USING (scope, key, window_start)
WHERE max_count > 0 AND count > max_count
ORDER BY priority LIMIT 1
