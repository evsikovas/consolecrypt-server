-- Storage accounting for quotas (security review MEDIUM-2): bytes of live
-- ciphertext per vault, maintained by the push transaction under the
-- vault_sequences row lock.
ALTER TABLE vault_sequences ADD COLUMN stored_bytes bigint NOT NULL DEFAULT 0 CHECK (stored_bytes >= 0);
UPDATE vault_sequences s
   SET stored_bytes = COALESCE((SELECT sum(octet_length(o.ciphertext))
                                  FROM vault_objects o
                                 WHERE o.vault_id = s.vault_id AND NOT o.deleted), 0);
