-- Vault epoch (protocol 1.3): random at vault creation; the operator rotates
-- it after restoring the server from a backup (`consolecrypt-server admin
-- rotate-epoch`) so clients can detect the rollback and re-push local data.
ALTER TABLE vaults ADD COLUMN epoch uuid NOT NULL DEFAULT gen_random_uuid();
