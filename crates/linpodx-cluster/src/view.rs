//! Cross-node container view aggregator.
//!
//! Calls each alive (or stale) peer's `/api/v1/containers` endpoint, parses the JSON
//! body into [`ContainerSummary`], and merges everything with the local-node listing
//! into a single [`ClusterContainerEntry`] vector. A peer that fails to respond is
//! skipped (logged at `debug`) — partial results are preferred over a hard failure.

use crate::peer::PeerInfo;
use crate::ClusterError;
use linpodx_common::ipc::responses::ClusterContainerEntry;
use linpodx_common::state::ContainerSummary;
use std::time::Duration;
use tracing::{debug, instrument};

/// Default deadline for one peer's container fetch. Slightly longer than the gossip
/// ping because we're transferring a list, not a heartbeat.
pub const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 8;

/// Aggregate local + remote containers into one vector, tagged with `node_id`.
///
/// * `local_node_id` — the identifier the local daemon advertises (callers usually
///   read this from the cluster config; the IPC layer treats `"local"` as a sentinel).
/// * `local_containers` — the result of `podman.list(true)` on the local node.
/// * `peers` — only entries with `Alive`/`Stale` status are queried.
/// * `token` — optional bearer token used for cross-node REST calls.
#[instrument(skip(local_containers, peers, http))]
pub async fn aggregate_containers(
    local_node_id: &str,
    local_containers: &[ContainerSummary],
    peers: &[PeerInfo],
    http: &reqwest::Client,
    token: Option<&str>,
) -> Vec<ClusterContainerEntry> {
    let mut out: Vec<ClusterContainerEntry> = local_containers
        .iter()
        .map(|c| ClusterContainerEntry {
            node_id: local_node_id.to_string(),
            container: c.clone(),
        })
        .collect();

    for peer in crate::gossip::alive_or_stale(peers) {
        match fetch_peer_containers(http, peer, token).await {
            Ok(items) => {
                for c in items {
                    out.push(ClusterContainerEntry {
                        node_id: peer.node_id.clone(),
                        container: c,
                    });
                }
            }
            Err(e) => {
                debug!(
                    node_id = %peer.node_id,
                    error = %e,
                    "view: peer container fetch failed (omitting from result)"
                );
            }
        }
    }
    out
}

async fn fetch_peer_containers(
    http: &reqwest::Client,
    peer: &PeerInfo,
    token: Option<&str>,
) -> Result<Vec<ContainerSummary>, ClusterError> {
    let url = build_containers_url(&peer.addr);
    let mut req = http
        .get(&url)
        .timeout(Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ClusterError::Http(format!("send {}: {e}", peer.node_id)))?;
    if !resp.status().is_success() {
        return Err(ClusterError::Http(format!(
            "peer {} returned status {}",
            peer.node_id,
            resp.status()
        )));
    }
    resp.json::<Vec<ContainerSummary>>()
        .await
        .map_err(|e| ClusterError::Http(format!("parse {}: {e}", peer.node_id)))
}

fn build_containers_url(addr: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    let http_addr = if let Some(rest) = trimmed.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        trimmed.to_string()
    };
    format!("{http_addr}/api/v1/containers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerStatus;
    use chrono::Utc;
    use linpodx_common::state::{ContainerState, ContainerSummary};
    use linpodx_common::types::ContainerId;

    fn sample_container(id: &str, name: &str) -> ContainerSummary {
        ContainerSummary {
            id: ContainerId(id.into()),
            names: vec![name.into()],
            image: "alpine:latest".into(),
            state: ContainerState::Running,
            status: "Up".into(),
            created: Utc::now(),
            command: None,
            ports: vec![],
        }
    }

    #[tokio::test]
    async fn aggregate_with_no_peers_returns_local_only() {
        let local = vec![sample_container("c1", "local-a")];
        let http = reqwest::Client::new();
        let result = aggregate_containers("node-local", &local, &[], &http, None).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_id, "node-local");
        assert_eq!(result[0].container.id.0, "c1");
    }

    #[tokio::test]
    async fn aggregate_skips_unreachable_peer_keeps_local() {
        let local = vec![sample_container("c1", "local-a")];
        let now = Utc::now();
        let peers = vec![PeerInfo {
            node_id: "node-b".into(),
            // Pin to a port we know is closed; reqwest will fail-fast.
            addr: "http://127.0.0.1:1".into(),
            status: PeerStatus::Alive,
            last_seen: now,
            joined_at: now,
        }];
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();
        let result = aggregate_containers("node-local", &local, &peers, &http, None).await;
        // Local row survives; failed peer row omitted.
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_id, "node-local");
    }

    #[test]
    fn containers_url_supports_ws_and_wss() {
        assert_eq!(
            build_containers_url("ws://127.0.0.1:7878"),
            "http://127.0.0.1:7878/api/v1/containers"
        );
        assert_eq!(
            build_containers_url("wss://x.example:7878/"),
            "https://x.example:7878/api/v1/containers"
        );
    }
}
