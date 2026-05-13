-- Phase 17 — crypto hardening + supply-chain finalisation schema.
--
-- This migration extends the Phase 16 snapshot/pin/plugin tables with the
-- columns and tables the three Phase 17 streams need:
--
--   * Stream A (runtime)   — argon2id KDF + snapshot key rotation. Adds
--                            kdf_algorithm / kdf_params / rotated_from /
--                            rotated_at columns on `snapshots` so the daemon
--                            can answer rotation status without re-reading
--                            every meta.json side-car.
--
--   * Stream C (security)  — TOFU time-based auto-disable. Adds the
--                            `tofu_expires_at` column on `pinned_clients` (set
--                            when an enrolment happens while a TOFU expiry is
--                            configured) and a brand-new
--                            `plugin_key_revocations` table that Raft uses to
--                            propagate revoke events cluster-wide.
--
-- Columns are NULLable / defaulted so existing Phase 16 rows stay valid. The
-- on-disk meta side-car remains the source of truth for snapshot crypto
-- params; the columns are a daemon-side index for the JSON-RPC `snapshot.*`
-- arms.

ALTER TABLE snapshots ADD COLUMN kdf_algorithm TEXT;
ALTER TABLE snapshots ADD COLUMN kdf_params TEXT;
ALTER TABLE snapshots ADD COLUMN rotated_from_snapshot_id INTEGER;
ALTER TABLE snapshots ADD COLUMN rotated_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_snapshots_kdf_algorithm ON snapshots(kdf_algorithm);
CREATE INDEX IF NOT EXISTS idx_snapshots_rotated_from ON snapshots(rotated_from_snapshot_id);

ALTER TABLE pinned_clients ADD COLUMN tofu_expires_at INTEGER;

CREATE TABLE IF NOT EXISTS plugin_key_revocations (
    publisher     TEXT    NOT NULL,
    fingerprint   TEXT    NOT NULL,
    reason        TEXT,
    revoked_at    INTEGER NOT NULL,
    propagated_to TEXT    NOT NULL DEFAULT '[]',
    PRIMARY KEY (publisher, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_plugin_key_revocations_revoked_at
    ON plugin_key_revocations(revoked_at);
