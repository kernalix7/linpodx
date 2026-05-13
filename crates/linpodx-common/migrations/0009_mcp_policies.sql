-- Phase 2E: MCP per-method approval policy. Replaces (and extends) the Phase 2D
-- bridge-startup `allowlist` Vec<String> by storing structured rules across daemon
-- restarts. `tools/call` may be further qualified by `tool_name`; other methods leave
-- `tool_name` NULL.

CREATE TABLE IF NOT EXISTS mcp_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    method      TEXT    NOT NULL,                                           -- "tools/call", "resources/read", ...
    tool_name   TEXT,                                                       -- only used when method = "tools/call"
    decision    TEXT    NOT NULL,                                           -- auto_allow | prompt | deny | audit_only
    note        TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(method, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_policies_method  ON mcp_policies(method);
