-- linpodx schema initialization (Phase 0)
-- Phase 1+ migrations add sandbox_profiles, audit_log, snapshots, mcp_sessions, etc.
-- IMPORTANT: migration files are append-only and never modified once shipped
-- (sqlx::migrate! verifies their checksums).

CREATE TABLE IF NOT EXISTS _schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO _schema_meta(key, value) VALUES ('schema_version', '0');
INSERT OR IGNORE INTO _schema_meta(key, value)
    VALUES ('initialized_at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
