-- Phase 6: WASM plugin registry. One row per installed plugin. Plugin files live on
-- disk under the user's data dir; this table only tracks metadata + enabled flag.

CREATE TABLE IF NOT EXISTS plugins (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    version         TEXT    NOT NULL,
    manifest_path   TEXT    NOT NULL,                                       -- absolute path to linpodx-plugin.toml
    wasm_path       TEXT    NOT NULL,                                       -- absolute path to .wasm
    hooks           TEXT    NOT NULL,                                       -- JSON array, e.g. ["approval"]
    enabled         INTEGER NOT NULL DEFAULT 1,
    installed_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_plugins_enabled ON plugins(enabled);
