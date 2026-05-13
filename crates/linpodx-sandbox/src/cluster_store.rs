//! SQLite-backed implementation of `linpodx_cluster::PeerStore` (Phase 9).
//!
//! Each row in the `cluster_peers` table (migration 0013) maps to one [`PeerInfo`].
//! The store is the bridge between the DB-agnostic gossip layer in `linpodx-cluster`
//! and the daemon's audit log: `upsert` records `ClusterPeerJoined`, `remove` records
//! `ClusterPeerLeft`, and the dispatcher records `ClusterViewServed` after a
//! `cluster_container_view` request.

use crate::audit::{self, AuditKind};
use chrono::{DateTime, TimeZone, Utc};
use linpodx_cluster::peer::PeerInfo;
use linpodx_cluster::store::PeerStore;
use linpodx_cluster::{ClusterError, PeerStatus, Result as ClusterResult};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::warn;

/// SQLite-backed peer registry. Wrap in `Arc::new(...)` and pass to gossip / dispatch
/// as `Arc<dyn PeerStore>`.
pub struct ClusterStore {
    db: Arc<Database>,
    audit: Arc<dyn AuditSink>,
}

impl ClusterStore {
    pub fn new(db: Arc<Database>, audit: Arc<dyn AuditSink>) -> Self {
        Self { db, audit }
    }

    pub fn database(&self) -> &Arc<Database> {
        &self.db
    }
}

impl PeerStore for ClusterStore {
    fn list(&self) -> Pin<Box<dyn Future<Output = ClusterResult<Vec<PeerInfo>>> + Send + '_>> {
        Box::pin(async move {
            let rows: Vec<PeerRow> = sqlx::query_as::<_, PeerRow>(
                "SELECT node_id, addr, status, last_seen, joined_at \
                 FROM cluster_peers ORDER BY id ASC",
            )
            .fetch_all(self.db.pool())
            .await
            .map_err(|e| ClusterError::Storage(format!("list peers: {e}")))?;
            Ok(rows.into_iter().map(PeerRow::into_info).collect())
        })
    }

    fn upsert(
        &self,
        node_id: String,
        addr: String,
    ) -> Pin<Box<dyn Future<Output = ClusterResult<PeerInfo>> + Send + '_>> {
        Box::pin(async move {
            if node_id.trim().is_empty() {
                return Err(ClusterError::InvalidAddr(format!(
                    "empty node_id (addr='{addr}')"
                )));
            }
            if addr.trim().is_empty() {
                return Err(ClusterError::InvalidAddr(format!(
                    "empty addr (node_id='{node_id}')"
                )));
            }
            let now = Utc::now();
            let now_str = format_ts(now);
            // Upsert keyed on node_id: re-joining a known node refreshes addr / status
            // and bumps last_seen, but preserves joined_at on conflict.
            sqlx::query(
                "INSERT INTO cluster_peers (node_id, addr, status, last_seen, joined_at) \
                 VALUES (?, ?, 'alive', ?, ?) \
                 ON CONFLICT(node_id) DO UPDATE SET \
                    addr = excluded.addr, \
                    status = 'alive', \
                    last_seen = excluded.last_seen",
            )
            .bind(&node_id)
            .bind(&addr)
            .bind(&now_str)
            .bind(&now_str)
            .execute(self.db.pool())
            .await
            .map_err(|e| ClusterError::Storage(format!("upsert peer '{node_id}': {e}")))?;

            let row: PeerRow = sqlx::query_as::<_, PeerRow>(
                "SELECT node_id, addr, status, last_seen, joined_at \
                 FROM cluster_peers WHERE node_id = ?",
            )
            .bind(&node_id)
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| ClusterError::Storage(format!("re-fetch peer '{node_id}': {e}")))?;

            let info = row.into_info();
            let payload = json!({
                "node_id": info.node_id,
                "addr": info.addr,
                "joined_at": info.joined_at,
            });
            self.audit
                .record(
                    AuditSinkKind::ClusterPeerJoined,
                    None,
                    None,
                    payload.clone(),
                )
                .await;
            if let Err(e) =
                audit::append(&self.db, AuditKind::ClusterPeerJoined, None, None, payload).await
            {
                warn!(error = %e, "cluster upsert: local audit append failed");
            }
            Ok(info)
        })
    }

    fn remove(
        &self,
        node_id: String,
    ) -> Pin<Box<dyn Future<Output = ClusterResult<bool>> + Send + '_>> {
        Box::pin(async move {
            let result = sqlx::query("DELETE FROM cluster_peers WHERE node_id = ?")
                .bind(&node_id)
                .execute(self.db.pool())
                .await
                .map_err(|e| ClusterError::Storage(format!("remove peer '{node_id}': {e}")))?;
            let removed = result.rows_affected() > 0;
            if removed {
                let payload = json!({"node_id": node_id});
                self.audit
                    .record(AuditSinkKind::ClusterPeerLeft, None, None, payload.clone())
                    .await;
                if let Err(e) =
                    audit::append(&self.db, AuditKind::ClusterPeerLeft, None, None, payload).await
                {
                    warn!(error = %e, "cluster remove: local audit append failed");
                }
            }
            Ok(removed)
        })
    }

    fn touch_seen(
        &self,
        node_id: String,
        now: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = ClusterResult<()>> + Send + '_>> {
        Box::pin(async move {
            let now_str = format_ts(now);
            sqlx::query(
                "UPDATE cluster_peers SET last_seen = ?, status = 'alive' WHERE node_id = ?",
            )
            .bind(&now_str)
            .bind(&node_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| ClusterError::Storage(format!("touch_seen '{node_id}': {e}")))?;
            Ok(())
        })
    }

    fn sweep(
        &self,
        now: DateTime<Utc>,
        stale_after_secs: i64,
        dead_after_secs: i64,
    ) -> Pin<Box<dyn Future<Output = ClusterResult<usize>> + Send + '_>> {
        Box::pin(async move {
            // Compute the two cutoffs and roll the FSM forward in two UPDATE statements.
            // We compare textual timestamps lexicographically — the format produced by
            // `format_ts` is fixed-width and ISO-8601 so this is well-defined.
            let stale_cut = format_ts(now - chrono::Duration::seconds(stale_after_secs.max(0)));
            let dead_cut = format_ts(
                now - chrono::Duration::seconds(stale_after_secs.max(0) + dead_after_secs.max(0)),
            );
            let stale_res = sqlx::query(
                "UPDATE cluster_peers SET status = 'stale' \
                 WHERE status = 'alive' AND last_seen < ?",
            )
            .bind(&stale_cut)
            .execute(self.db.pool())
            .await
            .map_err(|e| ClusterError::Storage(format!("sweep alive→stale: {e}")))?;
            let dead_res = sqlx::query(
                "UPDATE cluster_peers SET status = 'dead' \
                 WHERE status = 'stale' AND last_seen < ?",
            )
            .bind(&dead_cut)
            .execute(self.db.pool())
            .await
            .map_err(|e| ClusterError::Storage(format!("sweep stale→dead: {e}")))?;
            Ok((stale_res.rows_affected() + dead_res.rows_affected()) as usize)
        })
    }
}

/// Record a `cluster_view_served` audit event. Called by the dispatcher after each
/// successful `cluster_container_view` response so the timeline shows who pulled the
/// cross-node view and when.
pub async fn record_view_served(
    db: &Arc<Database>,
    audit: &dyn AuditSink,
    peer_count: usize,
    container_count: usize,
) {
    let payload = json!({
        "peer_count": peer_count,
        "container_count": container_count,
    });
    audit
        .record(
            AuditSinkKind::ClusterViewServed,
            None,
            None,
            payload.clone(),
        )
        .await;
    if let Err(e) = audit::append(db, AuditKind::ClusterViewServed, None, None, payload).await {
        warn!(error = %e, "cluster view: local audit append failed");
    }
}

fn format_ts(ts: DateTime<Utc>) -> String {
    // Match the migration's `strftime('%Y-%m-%dT%H:%M:%fZ','now')` so lexicographic
    // comparison in `sweep` works across mixed sources (defaulted column + our writes).
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc.timestamp_opt(0, 0).single().unwrap_or_else(Utc::now))
}

#[derive(sqlx::FromRow)]
struct PeerRow {
    node_id: String,
    addr: String,
    status: String,
    last_seen: String,
    joined_at: String,
}

impl PeerRow {
    fn into_info(self) -> PeerInfo {
        PeerInfo {
            node_id: self.node_id,
            addr: self.addr,
            status: PeerStatus::parse(&self.status),
            last_seen: parse_ts(&self.last_seen),
            joined_at: parse_ts(&self.joined_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::NoopAuditSink;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("cluster-store-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    fn make_store(db: Arc<Database>) -> ClusterStore {
        ClusterStore::new(db, Arc::new(NoopAuditSink))
    }

    #[tokio::test]
    async fn empty_list_returns_no_peers() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));
        let peers = store.list().await.expect("list");
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn upsert_then_list_roundtrips() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));

        let info = store
            .upsert("node-a".into(), "wss://node-a:7878".into())
            .await
            .expect("upsert");
        assert_eq!(info.node_id, "node-a");
        assert_eq!(info.addr, "wss://node-a:7878");
        assert_eq!(info.status, PeerStatus::Alive);

        let peers = store.list().await.expect("list");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "node-a");

        // Audit row must exist.
        let row: (String,) = sqlx::query_as(
            "SELECT kind FROM audit_log WHERE kind = 'cluster_peer_joined' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .expect("audit row");
        assert_eq!(row.0, "cluster_peer_joined");
    }

    #[tokio::test]
    async fn upsert_existing_node_refreshes_addr_and_status() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));

        let first = store
            .upsert("node-a".into(), "wss://old:7878".into())
            .await
            .expect("first");
        let joined_first = first.joined_at;

        // Force the row stale so we can verify upsert resets it.
        sqlx::query("UPDATE cluster_peers SET status = 'stale' WHERE node_id = 'node-a'")
            .execute(db.pool())
            .await
            .unwrap();

        let second = store
            .upsert("node-a".into(), "wss://new:7878".into())
            .await
            .expect("second upsert");
        assert_eq!(second.addr, "wss://new:7878");
        assert_eq!(second.status, PeerStatus::Alive);
        // joined_at preserved.
        assert_eq!(second.joined_at.timestamp(), joined_first.timestamp());

        let peers = store.list().await.expect("list");
        assert_eq!(peers.len(), 1);
    }

    #[tokio::test]
    async fn remove_unknown_returns_false() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));
        let removed = store.remove("ghost".into()).await.expect("remove");
        assert!(!removed);
    }

    #[tokio::test]
    async fn remove_known_returns_true_and_audits() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));
        store
            .upsert("node-x".into(), "wss://x:7878".into())
            .await
            .unwrap();
        let removed = store.remove("node-x".into()).await.expect("remove");
        assert!(removed);
        assert!(store.list().await.unwrap().is_empty());

        let row: (String,) = sqlx::query_as(
            "SELECT kind FROM audit_log WHERE kind = 'cluster_peer_left' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .expect("audit row");
        assert_eq!(row.0, "cluster_peer_left");
    }

    #[tokio::test]
    async fn touch_seen_resets_alive_and_bumps_timestamp() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));
        store
            .upsert("node-a".into(), "wss://a:7878".into())
            .await
            .unwrap();
        // Force stale.
        sqlx::query(
            "UPDATE cluster_peers SET status = 'stale', last_seen = '2000-01-01T00:00:00.000Z' \
             WHERE node_id = 'node-a'",
        )
        .execute(db.pool())
        .await
        .unwrap();

        let now = Utc::now();
        store.touch_seen("node-a".into(), now).await.expect("touch");

        let peers = store.list().await.expect("list");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].status, PeerStatus::Alive);
        assert!(peers[0].last_seen.timestamp() >= now.timestamp() - 1);
    }

    #[tokio::test]
    async fn sweep_alive_to_stale_and_stale_to_dead() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));

        // Three peers: fresh, stale-eligible, dead-eligible.
        let now = Utc::now();
        store
            .upsert("fresh".into(), "wss://fresh:1".into())
            .await
            .unwrap();
        store
            .upsert("aging".into(), "wss://aging:2".into())
            .await
            .unwrap();
        store
            .upsert("ancient".into(), "wss://ancient:3".into())
            .await
            .unwrap();

        // Backdate `aging` 2 minutes (stale-eligible at 60s threshold).
        let aging_ts = format_ts(now - chrono::Duration::seconds(120));
        sqlx::query("UPDATE cluster_peers SET last_seen = ? WHERE node_id = 'aging'")
            .bind(&aging_ts)
            .execute(db.pool())
            .await
            .unwrap();
        // Backdate `ancient` 10 minutes AND mark stale (dead-eligible after stale 240s
        // → cumulative cutoff 300s, so 600s-old crosses both lines).
        let ancient_ts = format_ts(now - chrono::Duration::seconds(600));
        sqlx::query(
            "UPDATE cluster_peers SET last_seen = ?, status = 'stale' WHERE node_id = 'ancient'",
        )
        .bind(&ancient_ts)
        .execute(db.pool())
        .await
        .unwrap();

        let changed = store.sweep(now, 60, 240).await.expect("sweep");
        // One alive→stale (aging) + one stale→dead (ancient) = 2 row changes.
        assert_eq!(changed, 2);

        let peers = store.list().await.expect("list");
        let by_id = |id: &str| peers.iter().find(|p| p.node_id == id).cloned().unwrap();
        assert_eq!(by_id("fresh").status, PeerStatus::Alive);
        assert_eq!(by_id("aging").status, PeerStatus::Stale);
        assert_eq!(by_id("ancient").status, PeerStatus::Dead);
    }

    #[tokio::test]
    async fn sweep_is_idempotent_on_repeat() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));
        store.upsert("p".into(), "wss://p:1".into()).await.unwrap();
        let now = Utc::now();
        let first = store.sweep(now, 60, 240).await.expect("sweep first");
        let second = store.sweep(now, 60, 240).await.expect("sweep second");
        assert_eq!(first, 0);
        assert_eq!(second, 0);
    }

    #[tokio::test]
    async fn upsert_rejects_empty_inputs() {
        let db = Arc::new(fresh_db().await);
        let store = make_store(Arc::clone(&db));
        let r = store.upsert("".into(), "wss://x:1".into()).await;
        assert!(matches!(r, Err(ClusterError::InvalidAddr(_))));
        let r2 = store.upsert("node-a".into(), "".into()).await;
        assert!(matches!(r2, Err(ClusterError::InvalidAddr(_))));
    }

    #[tokio::test]
    async fn record_view_served_writes_audit_row() {
        let db = Arc::new(fresh_db().await);
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        record_view_served(&db, sink.as_ref(), 3, 17).await;
        let row: (String, String) = sqlx::query_as(
            "SELECT kind, payload FROM audit_log WHERE kind = 'cluster_view_served' \
             ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .expect("audit row");
        assert_eq!(row.0, "cluster_view_served");
        assert!(row.1.contains("\"peer_count\":3"));
        assert!(row.1.contains("\"container_count\":17"));
    }
}
