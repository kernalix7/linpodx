//! Phase 14 Stream C — HTTP transport for the [`crate::election::RaftNode`].
//!
//! Three POST endpoints are mounted under `/cluster/raft/` by the daemon:
//!
//! * `POST /cluster/raft/append`   → `Raft::append_entries`
//! * `POST /cluster/raft/vote`     → `Raft::vote`
//! * `POST /cluster/raft/snapshot` → `Raft::install_snapshot`
//!
//! The wire format is JSON (matches openraft 0.9 with `serde` feature). v0.1
//! has no auth on the Raft endpoints — they are expected to be reachable only
//! on the cluster overlay network. A follow-up will reuse the Phase 7 bearer
//! token / mTLS plumbing once cluster-membership UX is settled.
//!
//! `RaftHttpFactory` is the [`openraft::RaftNetworkFactory`] implementation
//! the production daemon plugs into [`crate::election::RaftNode::start`] (in
//! place of the placeholder `NoopNetworkFactory`). It dials peer URLs with
//! the same reqwest client the gossip layer uses.

use std::sync::Arc;
use std::time::Duration;

use crate::election::{LinpodxRaft, NodeId};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use openraft::error::{InstallSnapshotError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;
use serde::de::DeserializeOwned;
use tracing::{debug, warn};

/// Build the axum sub-router for the Raft HTTP transport. Mount it on the
/// daemon's main router under `/cluster/raft` (the daemon does the
/// `.nest("/cluster/raft", raft_router(node))` call).
pub fn raft_router(node: Arc<crate::election::RaftNode>) -> Router {
    Router::new()
        .route("/append", post(handle_append))
        .route("/vote", post(handle_vote))
        .route("/snapshot", post(handle_snapshot))
        .with_state(node)
}

async fn handle_append(
    State(node): State<Arc<crate::election::RaftNode>>,
    Json(req): Json<AppendEntriesRequest<LinpodxRaft>>,
) -> impl IntoResponse {
    match node.raft().append_entries(req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            debug!(error = %e, "raft.http: append_entries handler errored");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn handle_vote(
    State(node): State<Arc<crate::election::RaftNode>>,
    Json(req): Json<VoteRequest<NodeId>>,
) -> impl IntoResponse {
    match node.raft().vote(req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            debug!(error = %e, "raft.http: vote handler errored");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn handle_snapshot(
    State(node): State<Arc<crate::election::RaftNode>>,
    Json(req): Json<InstallSnapshotRequest<LinpodxRaft>>,
) -> impl IntoResponse {
    match node.raft().install_snapshot(req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            debug!(error = %e, "raft.http: install_snapshot handler errored");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound side — `RaftHttpFactory` + `RaftHttpClient` impl `RaftNetwork`.
// ---------------------------------------------------------------------------

/// Default request timeout used by the outbound transport. Kept short so a
/// dead peer never wedges an election round.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

/// `RaftNetworkFactory` impl that dials peer URLs derived from the openraft
/// `BasicNode.addr` field. The factory is `Clone` so openraft can spawn one
/// `RaftHttpClient` per replication target.
#[derive(Debug, Clone)]
pub struct RaftHttpFactory {
    http: reqwest::Client,
    timeout: Duration,
}

impl RaftHttpFactory {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(DEFAULT_RPC_TIMEOUT)
            .timeout(DEFAULT_RPC_TIMEOUT)
            .user_agent(concat!("linpodx-raft/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    pub fn with_client(http: reqwest::Client) -> Self {
        Self {
            http,
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }
}

impl Default for RaftHttpFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl RaftNetworkFactory<LinpodxRaft> for RaftHttpFactory {
    type Network = RaftHttpClient;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        RaftHttpClient {
            http: self.http.clone(),
            base_url: normalize_base_url(&node.addr),
            target,
            timeout: self.timeout,
        }
    }
}

/// Per-peer outbound HTTP client. `base_url` is the peer's `host:port` (or a
/// pre-prefixed URL); `target` is the openraft NodeId we're talking to and is
/// only used for log lines.
#[derive(Debug, Clone)]
pub struct RaftHttpClient {
    http: reqwest::Client,
    base_url: String,
    target: NodeId,
    timeout: Duration,
}

impl RaftHttpClient {
    fn url(&self, path: &str) -> String {
        format!("{}/cluster/raft/{path}", self.base_url)
    }

    async fn post_json<Req, Resp>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, RaftError<NodeId>>>
    where
        Req: serde::Serialize,
        Resp: DeserializeOwned,
    {
        let resp = self
            .http
            .post(self.url(path))
            .timeout(self.timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                warn!(target = self.target, error = %e, path, "raft.http: send failed");
                RPCError::Unreachable(Unreachable::new(&e))
            })?;
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(target = self.target, %status, path, "raft.http: non-2xx");
            return Err(RPCError::Unreachable(Unreachable::new(
                &std::io::Error::other(format!("peer returned {status}")),
            )));
        }
        let parsed = resp.json::<Resp>().await.map_err(|e| {
            warn!(target = self.target, error = %e, path, "raft.http: response decode failed");
            RPCError::Unreachable(Unreachable::new(&e))
        })?;
        Ok(parsed)
    }
}

impl RaftNetwork<LinpodxRaft> for RaftHttpClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<LinpodxRaft>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.post_json("append", &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<LinpodxRaft>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        // Re-wrap the generic error chain — install_snapshot has its own
        // `RaftError<_, InstallSnapshotError>` but the wire impl is the same
        // shape (Unreachable on transport failure). We do the conversion
        // inline rather than via post_json's signature.
        let url = self.url("snapshot");
        let resp = self
            .http
            .post(url)
            .timeout(self.timeout)
            .json(&rpc)
            .send()
            .await
            .map_err(|e| {
                warn!(target = self.target, error = %e, "raft.http: install_snapshot send failed");
                RPCError::<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>::Unreachable(
                    Unreachable::new(&e),
                )
            })?;
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(target = self.target, %status, "raft.http: install_snapshot non-2xx");
            return Err(RPCError::Unreachable(Unreachable::new(
                &std::io::Error::other(format!("peer returned {status}")),
            )));
        }
        let parsed = resp.json::<InstallSnapshotResponse<NodeId>>().await.map_err(|e| {
            warn!(target = self.target, error = %e, "raft.http: install_snapshot decode failed");
            RPCError::Unreachable(Unreachable::new(&e))
        })?;
        Ok(parsed)
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.post_json("vote", &rpc).await
    }
}

/// Normalize a `BasicNode.addr` string into a base URL suitable for prefixing
/// the `/cluster/raft/...` path. Accepts bare `host:port`, `http(s)://...`,
/// and `ws(s)://...` (the gossip layer stores the WebSocket URL — we strip
/// the scheme back to plain HTTP).
fn normalize_base_url(addr: &str) -> String {
    let trimmed = addr.trim().trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix("wss://") {
        return format!("https://{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return format!("http://{rest}");
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    format!("http://{trimmed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_base_url_handles_common_prefixes() {
        assert_eq!(
            normalize_base_url("127.0.0.1:7878"),
            "http://127.0.0.1:7878"
        );
        assert_eq!(
            normalize_base_url("http://node-a:7878"),
            "http://node-a:7878"
        );
        assert_eq!(
            normalize_base_url("https://node-a:7878/"),
            "https://node-a:7878"
        );
        assert_eq!(normalize_base_url("ws://node-b:7878"), "http://node-b:7878");
        assert_eq!(
            normalize_base_url("wss://node-b:7878"),
            "https://node-b:7878"
        );
    }

    #[tokio::test]
    async fn factory_builds_client_with_target() {
        let mut factory = RaftHttpFactory::new();
        let node = BasicNode::new("127.0.0.1:9999".to_string());
        let client = factory.new_client(42, &node).await;
        assert_eq!(client.target, 42);
        assert_eq!(client.base_url, "http://127.0.0.1:9999");
        assert_eq!(
            client.url("append"),
            "http://127.0.0.1:9999/cluster/raft/append"
        );
    }

    #[tokio::test]
    async fn raft_router_mounts_three_routes() {
        // Smoke test that the router builds with a real node — we don't
        // exercise the handlers here (that needs a TCP listener and is
        // covered by the integration tests).
        let node = Arc::new(
            crate::election::RaftNode::start(
                crate::election::RaftStartConfig {
                    bootstrap_single_node: false,
                    ..Default::default()
                },
                None,
                None,
            )
            .await
            .expect("start"),
        );
        let _router: Router = raft_router(Arc::clone(&node));
    }

    #[tokio::test]
    async fn vote_to_dead_peer_returns_unreachable() {
        let mut factory = RaftHttpFactory::with_client(
            reqwest::Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .unwrap(),
        );
        // Pick a port nothing is listening on — connect fails fast.
        let node = BasicNode::new("127.0.0.1:1".to_string());
        let mut client = factory.new_client(99, &node).await;
        let req = VoteRequest::new(openraft::Vote::new(1, 1), None);
        let res = client
            .vote(req, RPCOption::new(Duration::from_millis(200)))
            .await;
        assert!(
            matches!(res, Err(RPCError::Unreachable(_))),
            "expected Unreachable, got {res:?}"
        );
    }
}
