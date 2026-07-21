//! linpodx-cluster — peer-to-peer gossip + multi-node container view.
//!
//! Phase 9 entry crate. Stage 2-B (this commit) fills in the remaining modules:
//! [`peer`] (PeerInfo record), [`store`] (PeerStore trait — DB-agnostic), [`gossip`]
//! (periodic ping + sweep loop), [`view`] (cross-node container aggregator). The
//! concrete SQLite-backed `PeerStore` lives in `linpodx-sandbox::cluster_store` so this
//! crate stays free of any DB dependency. Transport reuses the Phase 7/8 remote daemon
//! (axum + WebSocket + optional mTLS) — there is no separate cluster port.

#![forbid(unsafe_code)]

pub mod election;
pub mod gossip;
pub mod k8s;
pub mod peer;
pub mod raft_http;
pub mod store;
pub mod view;

pub use election::{
    node_id_from_string, AppData, AppResponse, ClusterStateSnapshot, LeaderState,
    MembershipNodeView, MembershipSnapshot, MetricSnapshot, NoopVoteSink, PluginRevocationSink,
    RaftNode, RaftStartConfig, SqliteVoteSink, VoteSink,
};
pub use k8s::K8sAdapter;
pub use peer::PeerInfo;
pub use raft_http::{raft_router, raft_router_with_auth, RaftHttpClient, RaftHttpFactory};
pub use store::PeerStore;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClusterError {
    #[error("not yet implemented (Stage 2-B): {0}")]
    NotImplemented(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http error: {0}")]
    Http(String),
    #[error("peer '{0}' not found")]
    PeerNotFound(String),
    #[error("peer '{0}' already joined")]
    PeerDuplicate(String),
    #[error("invalid peer addr '{0}'")]
    InvalidAddr(String),
    #[error("storage error: {0}")]
    Storage(String),
}

pub type Result<T> = std::result::Result<T, ClusterError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Alive,
    Stale,
    Dead,
}

impl PeerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Stale => "stale",
            Self::Dead => "dead",
        }
    }

    /// Parse the textual form stored in the `cluster_peers.status` column. Unknown
    /// strings are mapped to `Stale` rather than erroring — the status column is meant
    /// to be self-healing on the next gossip sweep.
    pub fn parse(s: &str) -> Self {
        match s {
            "alive" => Self::Alive,
            "dead" => Self::Dead,
            _ => Self::Stale,
        }
    }
}
