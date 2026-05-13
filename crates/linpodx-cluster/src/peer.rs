//! Peer record types shared by [`crate::store`] and [`crate::gossip`].

use crate::PeerStatus;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_id: String,
    pub addr: String,
    pub status: PeerStatus,
    pub last_seen: DateTime<Utc>,
    pub joined_at: DateTime<Utc>,
}

impl PeerInfo {
    pub fn new(node_id: impl Into<String>, addr: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            node_id: node_id.into(),
            addr: addr.into(),
            status: PeerStatus::Alive,
            last_seen: now,
            joined_at: now,
        }
    }
}
