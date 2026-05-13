-- Phase 7: pluggable snapshot backend. Existing rows default to 'podman_commit'
-- (matches Phase 2 behavior). New backends ('overlayfs', 'btrfs') will fill in their
-- own kind string via the SnapshotBackendKind enum.

ALTER TABLE snapshots ADD COLUMN backend TEXT NOT NULL DEFAULT 'podman_commit';

CREATE INDEX IF NOT EXISTS idx_snapshots_backend ON snapshots(backend);
