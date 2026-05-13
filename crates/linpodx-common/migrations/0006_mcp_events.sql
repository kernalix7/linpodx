-- Phase 2D: MCP bridge events. Each row is one stdio message (host→container or
-- container→host) the bridge observed. Best-effort JSON parsing extracts `method`;
-- raw bytes are stored in `payload` (truncated to 8 KiB).

CREATE TABLE IF NOT EXISTS mcp_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES mcp_sessions(id) ON DELETE CASCADE,
    ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    direction   TEXT    NOT NULL,    -- 'host_to_container' | 'container_to_host'
    tool_name   TEXT,                -- best-effort JSON-RPC `method` extract
    payload     TEXT    NOT NULL,    -- raw bytes (UTF-8 lossy, truncated)
    decision    TEXT                 -- 'allowed' | 'denied' | 'audit_only'
);

CREATE INDEX IF NOT EXISTS idx_mcp_events_session   ON mcp_events(session_id);
CREATE INDEX IF NOT EXISTS idx_mcp_events_tool      ON mcp_events(tool_name);
CREATE INDEX IF NOT EXISTS idx_mcp_events_ts        ON mcp_events(ts);
