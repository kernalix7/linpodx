-- Phase 14 Stream C: Raft leader-elect persistence.
-- Two tiny tables — `raft_state` holds the current persisted vote and
-- last-applied log id (one row, key='vote' / key='last_applied' / key='node_id'),
-- `raft_log` is reserved for future durable log persistence (v0.1 keeps the log
-- in memory because the only state the leader-elect needs across restarts is
-- the vote — no application log entries are ever appended).
--
-- The schema is intentionally key/value: openraft 0.9's `Vote` and `LogId`
-- are JSON-serializable, so callers store them encoded as TEXT. This keeps the
-- migration stable across openraft minor-version bumps.

CREATE TABLE IF NOT EXISTS raft_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS raft_log (
    log_index INTEGER PRIMARY KEY,
    term      INTEGER NOT NULL,
    payload   TEXT    NOT NULL,                                                  -- JSON-encoded openraft::Entry
    appended_at TEXT  NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_raft_log_term ON raft_log(term);
