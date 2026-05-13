-- Phase 2B: container snapshot index. The snapshot itself is a Podman image (created via
-- `podman commit`); this table tracks the daemon-visible metadata so the UI / CLI can list
-- snapshots per container, reason about lineage (parent_id), and clean up.

CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id TEXT    NOT NULL,
    label        TEXT,
    image_ref    TEXT    NOT NULL,
    parent_id    INTEGER REFERENCES snapshots(id) ON DELETE SET NULL,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    size_bytes   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_snapshots_container ON snapshots(container_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_created   ON snapshots(created_at);
