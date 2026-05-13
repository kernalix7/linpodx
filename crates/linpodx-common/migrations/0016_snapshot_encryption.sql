-- Phase 16 Stream B: at-rest encryption metadata for snapshot rows.
--
-- The actual ciphertext lives on disk under
-- $LINPODX_ENCRYPTED_SNAPSHOT_ROOT (default $XDG_DATA_HOME/linpodx/encrypted-snapshots/)
-- as a per-image-ref `<sha8>/blob.enc` + `<sha8>/meta.json` pair. These columns
-- are a daemon-side index so the JSON-RPC `snapshot.encryption_status` call can
-- answer without re-reading every side-car file.
--
-- Columns are NULLable / default-zero so existing snapshot rows (committed
-- before encryption was enabled) remain valid. The on-disk meta side-car is
-- the source of truth; rows are populated lazily by the dispatcher when the
-- side-car is detected.

ALTER TABLE snapshots ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshots ADD COLUMN algorithm TEXT;
ALTER TABLE snapshots ADD COLUMN key_source TEXT;
ALTER TABLE snapshots ADD COLUMN ciphertext_sha256 TEXT;

CREATE INDEX IF NOT EXISTS idx_snapshots_encrypted ON snapshots(encrypted);
