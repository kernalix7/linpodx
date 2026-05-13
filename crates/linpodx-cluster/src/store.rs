//! [`PeerStore`] trait — DB-agnostic interface used by [`crate::gossip`] and the
//! daemon-side dispatcher. The concrete SQLite-backed implementation lives in
//! `linpodx-sandbox::cluster_store::ClusterStore` to keep this crate free of any DB
//! dependency.

use crate::peer::PeerInfo;
use crate::Result;
use chrono::{DateTime, Utc};
use std::future::Future;
use std::pin::Pin;

/// Trait the dispatcher passes to gossip rounds. Returns boxed futures so trait objects
/// (`Arc<dyn PeerStore>`) work with the periodic gossip task — `async fn in trait` is
/// allowed in Rust 1.83 but does not yet support dyn dispatch.
pub trait PeerStore: Send + Sync {
    fn list(&self) -> Pin<Box<dyn Future<Output = Result<Vec<PeerInfo>>> + Send + '_>>;

    fn upsert(
        &self,
        node_id: String,
        addr: String,
    ) -> Pin<Box<dyn Future<Output = Result<PeerInfo>> + Send + '_>>;

    fn remove(&self, node_id: String) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + '_>>;

    /// Mark a peer as `Alive` and bump `last_seen` to `now`.
    fn touch_seen(
        &self,
        node_id: String,
        now: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Roll status forward based on `last_seen`:
    ///   alive → stale  after `stale_after_secs`
    ///   stale → dead   after `dead_after_secs` more (≥ `stale_after_secs + dead_after_secs`)
    /// Returns the number of rows that changed status.
    fn sweep(
        &self,
        now: DateTime<Utc>,
        stale_after_secs: i64,
        dead_after_secs: i64,
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + '_>>;
}
