-- Phase 1C: sandbox profile cache.
-- YAML files in $XDG_CONFIG_HOME/linpodx/profiles/*.yaml are the source of truth;
-- this table caches them for fast lookup and lets audit_log reference profile names
-- by foreign-key-style convention (no actual FK to keep audit_log decoupled if a
-- profile is removed mid-history).

CREATE TABLE IF NOT EXISTS sandbox_profile (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    yaml_content TEXT    NOT NULL,
    yaml_hash    TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_sandbox_profile_name ON sandbox_profile(name);
