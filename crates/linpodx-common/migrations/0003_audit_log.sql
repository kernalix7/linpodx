-- Phase 1C: append-only audit log with SHA-256 hash chain for tamper evidence.
-- this_hash = sha256(prev_hash_hex || serialized_payload_json). The first row's
-- prev_hash is 64 hex zeros. Verification re-computes the chain and reports the
-- first divergent seq, if any.

CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    profile_name TEXT,
    container_id TEXT,
    payload      TEXT    NOT NULL,             -- JSON object
    prev_hash    TEXT    NOT NULL,             -- 64-char hex SHA-256
    this_hash    TEXT    NOT NULL UNIQUE       -- 64-char hex SHA-256
);

CREATE INDEX IF NOT EXISTS idx_audit_log_profile ON audit_log(profile_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_kind    ON audit_log(kind);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts      ON audit_log(ts);
