-- Phase 4: distro instance registry. Every container created via `linpodx distro create`
-- gets one row here so the daemon can later list / enter / remove the instance and
-- reconstruct its persistent home volume name. The static template list is compiled into
-- `linpodx-distro::templates` and not stored in the DB.

CREATE TABLE IF NOT EXISTS distro_instances (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    kind          TEXT    NOT NULL,                                          -- DistroKind as_str
    container_id  TEXT    NOT NULL,
    image_ref     TEXT    NOT NULL,
    vm_mode       INTEGER NOT NULL DEFAULT 0,                                -- 0=ephemeral, 1=persistent home
    home_volume   TEXT,                                                      -- volume name when vm_mode=1
    auto_restart  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    removed_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_distro_instances_kind     ON distro_instances(kind);
CREATE INDEX IF NOT EXISTS idx_distro_instances_active   ON distro_instances(removed_at);
