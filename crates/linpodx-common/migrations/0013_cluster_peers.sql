-- Phase 9: cluster peer registry. One row per peer node the local daemon has joined
-- with. `addr` is the WebSocket URL used for gossip + container-view aggregation.
-- `last_seen` is touched after each successful gossip round; `status` is rolled
-- forward by the gossip task ('alive' → 'stale' after 60s no-response → 'dead' after
-- 300s).

CREATE TABLE IF NOT EXISTS cluster_peers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     TEXT    NOT NULL UNIQUE,
    addr        TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'alive',                            -- alive | stale | dead
    last_seen   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    joined_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_cluster_peers_status ON cluster_peers(status);
