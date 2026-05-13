//! Periodic gossip task — pings every alive peer's `/api/v1/version` endpoint,
//! touches `last_seen` on success, and rolls statuses forward on persistent failure.
//!
//! v0.1 keeps the protocol intentionally tiny: a successful HTTP 200 response from
//! `<peer.addr>/api/v1/version` is treated as proof of life. Anything else (timeout,
//! non-2xx, body parse error) leaves `last_seen` untouched; [`sweep_stale`] handles
//! the alive→stale→dead transitions on its own clock.
//!
//! Thresholds default to 60s (alive→stale) and 240s (stale→dead) — i.e. a peer must be
//! silent for 5 full minutes before it is declared dead. Both are passed in so tests
//! can compress them.

use crate::peer::PeerInfo;
use crate::store::PeerStore;
use crate::PeerStatus;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, instrument, trace, warn};

pub const DEFAULT_STALE_AFTER_SECS: i64 = 60;
pub const DEFAULT_DEAD_AFTER_SECS: i64 = 240;
pub const DEFAULT_GOSSIP_PERIOD_SECS: u64 = 15;
pub const DEFAULT_PING_TIMEOUT_SECS: u64 = 5;

/// Run a single gossip round: GET `/api/v1/version` against each peer, touch
/// `last_seen` on success. Failures are logged at `debug` level and left to
/// [`sweep_stale`].
#[instrument(skip(store, http))]
pub async fn run_round(store: Arc<dyn PeerStore>, http: &reqwest::Client) {
    let peers = match store.list().await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "gossip: peer list failed");
            return;
        }
    };
    let now = Utc::now();
    for peer in peers {
        // Skip dead peers — they stay dead until an explicit re-join.
        if peer.status == PeerStatus::Dead {
            continue;
        }
        let url = build_version_url(&peer.addr);
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Err(e) = store.touch_seen(peer.node_id.clone(), now).await {
                    warn!(error = %e, node_id = %peer.node_id, "gossip: touch_seen failed");
                }
                trace!(node_id = %peer.node_id, "gossip: ping ok");
            }
            Ok(resp) => {
                debug!(
                    node_id = %peer.node_id,
                    status = %resp.status(),
                    "gossip: peer returned non-2xx"
                );
            }
            Err(e) => {
                debug!(node_id = %peer.node_id, error = %e, "gossip: peer unreachable");
            }
        }
    }
}

/// Apply the alive→stale→dead state machine based on each peer's `last_seen`.
/// Idempotent — calling repeatedly with the same `now` is a no-op.
pub async fn sweep_stale(
    store: Arc<dyn PeerStore>,
    now: DateTime<Utc>,
    stale_after_secs: i64,
    dead_after_secs: i64,
) -> crate::Result<usize> {
    store.sweep(now, stale_after_secs, dead_after_secs).await
}

/// Spawn the periodic gossip + sweep loop. The returned handle owns the task; drop or
/// `abort()` it to stop. Callers typically hold the handle in the daemon's lifetime
/// state.
pub fn run_loop(
    store: Arc<dyn PeerStore>,
    http: reqwest::Client,
    period_secs: u64,
    stale_after_secs: i64,
    dead_after_secs: i64,
) -> JoinHandle<()> {
    let period = Duration::from_secs(period_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            run_round(Arc::clone(&store), &http).await;
            if let Err(e) = sweep_stale(
                Arc::clone(&store),
                Utc::now(),
                stale_after_secs,
                dead_after_secs,
            )
            .await
            {
                warn!(error = %e, "gossip: sweep_stale failed");
            }
        }
    })
}

/// Build a default reqwest client configured for short gossip pings — small connect /
/// total timeouts so a single dead peer never stalls a round, and rustls (matches the
/// workspace mTLS stack).
pub fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(DEFAULT_PING_TIMEOUT_SECS))
        .timeout(Duration::from_secs(DEFAULT_PING_TIMEOUT_SECS))
        .user_agent(concat!("linpodx-cluster/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Filter helper for callers that want only the live peers (used by the container view
/// aggregator). Treats both `Alive` and `Stale` as worth polling — a stale peer might
/// still answer a one-off REST call faster than the next gossip cycle catches up.
pub fn alive_or_stale(peers: &[PeerInfo]) -> Vec<&PeerInfo> {
    peers
        .iter()
        .filter(|p| matches!(p.status, PeerStatus::Alive | PeerStatus::Stale))
        .collect()
}

/// Phase 14/15 narrow hook — when a peer is added via `cluster join`, the
/// dispatcher (or a future feed-the-raft task) should also tell the Raft
/// engine about it so leader-election traffic can flow. v0.1 calls
/// [`crate::election::RaftNode::add_learner_with_audit`] which dials the peer's
/// HTTP transport AND records the membership change to the audit sink.
/// Best-effort — if the Raft handle is `None` (no leader-elect on this build)
/// the call is a no-op.
pub async fn raft_on_peer_added(raft: Option<&crate::election::RaftNode>, label: &str, addr: &str) {
    let Some(node) = raft else {
        return;
    };
    if let Err(e) = node
        .add_learner_with_audit(label.to_string(), normalize_addr_for_raft(addr))
        .await
    {
        debug!(label, error = %e, "raft membership add_learner failed");
    }
}

/// Phase 14/15 narrow hook — counterpart to [`raft_on_peer_added`]. Uses the
/// audit-aware `remove_node` so Raft demotions surface in the audit log.
pub async fn raft_on_peer_removed(raft: Option<&crate::election::RaftNode>, label: &str) {
    let Some(node) = raft else {
        return;
    };
    if let Err(e) = node.remove_node(label).await {
        debug!(label, error = %e, "raft membership remove_node failed");
    }
}

/// Phase 15 — periodic gossip → Raft membership sync. Runs every
/// `period.max(1s)` (clamped to avoid pathological tight loops in tests):
///
/// * Snapshots the live peer set from `store`.
/// * For each peer that is `Alive` and has been in the cluster long enough
///   (`promote_after`) — i.e. its `joined_at` is older than `now - promote_after`
///   — promotes it from learner to voter. Idempotent: already-voter peers are
///   silently no-ops via `Raft::change_membership`'s ReplaceAllVoters semantics.
/// * For each `Dead` peer that is currently a voter, removes it from the
///   voting set so quorum stays small.
///
/// Returns a tuple `(promoted_labels, removed_labels)` per round so callers /
/// tests can observe activity. Errors are logged at `warn!` and the loop
/// continues on the next tick.
pub async fn raft_membership_sync_round(
    raft: &crate::election::RaftNode,
    peers: &[PeerInfo],
    now: chrono::DateTime<Utc>,
    promote_after: chrono::Duration,
) -> (Vec<String>, Vec<String>) {
    let snap = raft.membership_snapshot();
    let voter_labels: std::collections::BTreeSet<String> =
        snap.voters.iter().filter_map(|v| v.label.clone()).collect();

    // Decide promotions: alive peers, joined_at + promote_after <= now, not yet voter.
    let mut to_promote: Vec<String> = Vec::new();
    for peer in peers {
        if peer.status != PeerStatus::Alive {
            continue;
        }
        if voter_labels.contains(&peer.node_id) {
            continue;
        }
        if now.signed_duration_since(peer.joined_at) >= promote_after {
            to_promote.push(peer.node_id.clone());
        }
    }

    // Decide removals: dead peers that are currently voters.
    let mut to_remove: Vec<String> = Vec::new();
    for peer in peers {
        if peer.status == PeerStatus::Dead && voter_labels.contains(&peer.node_id) {
            to_remove.push(peer.node_id.clone());
        }
    }

    let mut promoted = Vec::new();
    if !to_promote.is_empty() {
        // Build the new voter set: existing voters + new candidates.
        let mut all_labels: Vec<String> = voter_labels.iter().cloned().collect();
        for l in &to_promote {
            all_labels.push(l.clone());
        }
        // Drop the local node label here — promote_with_audit re-adds the local
        // numeric id internally so we don't need (and don't have) a label for it
        // in the labels arg necessarily; we simply pass everything we know about.
        match raft.promote_with_audit(&all_labels).await {
            Ok(newly) => {
                promoted = newly;
            }
            Err(e) => {
                tracing::warn!(error = %e, "raft membership: promote round failed");
            }
        }
    }

    let mut removed = Vec::new();
    for label in &to_remove {
        match raft.remove_node(label).await {
            Ok(()) => removed.push(label.clone()),
            Err(e) => {
                tracing::warn!(label, error = %e, "raft membership: remove round failed");
            }
        }
    }

    (promoted, removed)
}

/// Phase 15 — spawn the periodic gossip↔Raft membership sync loop. Returns the
/// background task handle so callers can `abort()` on shutdown. The loop ticks
/// every `period_secs` (clamped to >=1s), enumerates the gossip peer set, then
/// promotes Alive peers older than `promote_after_secs` and removes Dead voters.
pub fn run_raft_sync_loop(
    raft: Arc<crate::election::RaftNode>,
    store: Arc<dyn PeerStore>,
    period_secs: u64,
    promote_after_secs: i64,
) -> JoinHandle<()> {
    let period = Duration::from_secs(period_secs.max(1));
    let promote_after = chrono::Duration::seconds(promote_after_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let peers = match store.list().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "raft membership sync: peer list failed");
                    continue;
                }
            };
            let (_p, _r) =
                raft_membership_sync_round(raft.as_ref(), &peers, Utc::now(), promote_after).await;
        }
    })
}

/// Strip the gossip layer's `ws(s)://` scheme + trailing `/ipc` so the
/// remainder is a `host:port` for the Raft HTTP transport to reach.
fn normalize_addr_for_raft(addr: &str) -> String {
    let trimmed = addr.trim().trim_end_matches('/');
    let no_ipc = trimmed.strip_suffix("/ipc").unwrap_or(trimmed);
    let no_scheme = no_ipc
        .strip_prefix("wss://")
        .or_else(|| no_ipc.strip_prefix("ws://"))
        .or_else(|| no_ipc.strip_prefix("https://"))
        .or_else(|| no_ipc.strip_prefix("http://"))
        .unwrap_or(no_ipc);
    no_scheme.to_string()
}

fn build_version_url(addr: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    let http_addr = if let Some(rest) = trimmed.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        trimmed.to_string()
    };
    format!("{http_addr}/api/v1/version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_url_supports_ws_and_wss() {
        assert_eq!(
            build_version_url("ws://127.0.0.1:7878"),
            "http://127.0.0.1:7878/api/v1/version"
        );
        assert_eq!(
            build_version_url("wss://node-b.example:7878/"),
            "https://node-b.example:7878/api/v1/version"
        );
        assert_eq!(
            build_version_url("https://node-c:7878"),
            "https://node-c:7878/api/v1/version"
        );
    }

    #[test]
    fn normalize_addr_for_raft_strips_scheme_and_ipc_suffix() {
        assert_eq!(
            normalize_addr_for_raft("ws://node-a:7878/ipc"),
            "node-a:7878"
        );
        assert_eq!(normalize_addr_for_raft("wss://node-b:7878/"), "node-b:7878");
        assert_eq!(normalize_addr_for_raft("http://node-c:7878"), "node-c:7878");
        assert_eq!(normalize_addr_for_raft("node-d:7878"), "node-d:7878");
    }

    #[tokio::test]
    async fn raft_hooks_with_none_handle_are_noop() {
        // Should not panic — the helper short-circuits when the optional
        // Raft handle is None (which is the case in builds that disable
        // leader-elect).
        raft_on_peer_added(None, "alpha", "ws://1.2.3.4:7878/ipc").await;
        raft_on_peer_removed(None, "alpha").await;
    }

    #[test]
    fn alive_or_stale_excludes_dead() {
        let now = Utc::now();
        let peers = vec![
            PeerInfo {
                node_id: "a".into(),
                addr: "ws://a".into(),
                status: PeerStatus::Alive,
                last_seen: now,
                joined_at: now,
            },
            PeerInfo {
                node_id: "b".into(),
                addr: "ws://b".into(),
                status: PeerStatus::Stale,
                last_seen: now,
                joined_at: now,
            },
            PeerInfo {
                node_id: "c".into(),
                addr: "ws://c".into(),
                status: PeerStatus::Dead,
                last_seen: now,
                joined_at: now,
            },
        ];
        let filtered = alive_or_stale(&peers);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|p| p.node_id != "c"));
    }

    #[tokio::test]
    async fn raft_membership_sync_round_recently_joined_peer_is_not_promoted_yet() {
        // A peer that just joined (joined_at == now) is not yet eligible for
        // promotion (the promote_after window has not elapsed). The round
        // should be a no-op.
        use crate::election::{RaftNode, RaftStartConfig};
        let node = RaftNode::start(
            RaftStartConfig {
                node_id: 1,
                node_label: "alpha".into(),
                advertise_addr: "127.0.0.1:0".into(),
                heartbeat_ms: 50,
                election_timeout_min_ms: 200,
                election_timeout_max_ms: 400,
                bootstrap_single_node: true,
            },
            None,
            None,
        )
        .await
        .expect("start");
        let now = Utc::now();
        let peers = vec![PeerInfo {
            node_id: "freshly-joined".into(),
            addr: "ws://1.2.3.4:7878".into(),
            status: PeerStatus::Alive,
            last_seen: now,
            joined_at: now,
        }];
        let (promoted, removed) =
            raft_membership_sync_round(&node, &peers, now, chrono::Duration::seconds(5)).await;
        assert!(promoted.is_empty());
        assert!(removed.is_empty());
        node.shutdown().await;
    }
}
