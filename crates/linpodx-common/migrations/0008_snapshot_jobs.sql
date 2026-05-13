-- Phase 2E: async snapshot job tracker. `SnapshotJobCreate` returns a `job_id` and the
-- actual `podman commit` runs in a background tokio task that writes progress lines into
-- this table and emits `EventKind::Progress` notifications. On success the corresponding
-- `snapshots` row is filled in (snapshot_id below); on failure `error_message` is set.

CREATE TABLE IF NOT EXISTS snapshot_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          TEXT    NOT NULL UNIQUE,
    container_id    TEXT    NOT NULL,
    label           TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending',  -- pending | running | succeeded | failed | cancelled
    snapshot_id     INTEGER REFERENCES snapshots(id) ON DELETE SET NULL,
    image_ref       TEXT,
    last_progress   TEXT,
    error_message   TEXT,
    started_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    ended_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_snapshot_jobs_status     ON snapshot_jobs(status);
CREATE INDEX IF NOT EXISTS idx_snapshot_jobs_container  ON snapshot_jobs(container_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_jobs_started    ON snapshot_jobs(started_at);
