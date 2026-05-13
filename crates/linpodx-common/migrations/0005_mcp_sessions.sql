-- Phase 2C: per-container session row. A session is the lifetime of one container; it
-- groups audit log entries and MCP events for replay. Daemon inserts on ContainerCreate,
-- updates ended_at/status on ContainerRemove.

CREATE TABLE IF NOT EXISTS mcp_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id    TEXT    NOT NULL,
    container_name  TEXT    NOT NULL,
    profile_name    TEXT,
    started_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    ended_at        TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'   -- active | ended | aborted
);

CREATE INDEX IF NOT EXISTS idx_mcp_sessions_container ON mcp_sessions(container_id);
CREATE INDEX IF NOT EXISTS idx_mcp_sessions_status    ON mcp_sessions(status);
CREATE INDEX IF NOT EXISTS idx_mcp_sessions_started   ON mcp_sessions(started_at);
