-- Phase 5: snapshot tree support. The `snapshots` table already carries `parent_id`
-- (added in 0004), so this migration just reinforces the index that the GUI tree view
-- and `snapshot diff` queries depend on. No schema change.

CREATE INDEX IF NOT EXISTS idx_snapshots_parent ON snapshots(parent_id);
