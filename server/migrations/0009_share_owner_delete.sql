-- Protocol 1.8: owner-only delete with a restore window, and recipients
-- leaving a share. Documents stay signed opaque wire data (no plaintext/DEKs).

-- The last content revision (ciphertext + per-device envelopes) of an
-- owner-deleted item, kept until the restore window ends. The tombstone in
-- current_mutation stays the authoritative, signed state.
ALTER TABLE shared_items
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN restore_revision jsonb;
UPDATE shared_items SET deleted_at = updated_at WHERE deleted;
CREATE INDEX shared_items_restorable_idx
    ON shared_items (owner_user_id, id) WHERE restore_revision IS NOT NULL;

-- A recipient account that left an item. Its devices lose server access at
-- once (their shared_item_devices rows are removed); the row is cleared when
-- the owner's next signed manifest drops the account or explicitly adds a
-- new device of it (a fresh invitation).
CREATE TABLE shared_item_departures (
    share_id uuid NOT NULL REFERENCES shared_items (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    left_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (share_id, user_id)
);
