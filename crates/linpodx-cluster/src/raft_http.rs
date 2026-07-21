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
//!
//! ## Authentication
//!
//! The Raft endpoints share the cluster's bearer token — the same
//! `--remote-token` presented on the rest of the remote surface. Every cluster
//! node MUST be started with the same `--remote-token`; the daemon threads that
//! token into both [`raft_router_with_auth`] (inbound: rejects requests without
//! a matching `Authorization: Bearer <token>` header) and
//! [`RaftHttpFactory::with_token`] (outbound: attaches the header to every
//! append/vote/snapshot RPC). A single shared token is the simplest sound
//! design for a homogeneous cluster; per-peer tokens are intentionally not
//! modelled in v0.1 (a peer either speaks the cluster token or it is not a
//! member). Rejected inbound requests are audited via [`AuditSinkKind::RemoteAuthFailed`].

use std::sync::Arc;
use std::time::Duration;

use crate::election::{LinpodxRaft, NodeId};
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use openraft::error::{InstallSnapshotError, RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::net::SocketAddr;
use tracing::{debug, warn};

/// Build the unauthenticated axum sub-router for the Raft HTTP transport.
///
/// Retained for tests and single-process harnesses that mount the transport on
/// a loopback listener with no token. Production deployments MUST use
/// [`raft_router_with_auth`] so peer RPCs are gated on the cluster bearer token.
pub fn raft_router(node: Arc<crate::election::RaftNode>) -> Router {
    raft_router_with_auth(node, None, None)
}

/// State shared with the Raft bearer-token middleware. Cloned per request by
/// axum; both fields are cheap `Arc` handles.
#[derive(Clone)]
struct RaftAuthState {
    token: Arc<String>,
    audit: Option<Arc<dyn AuditSink>>,
}

/// Build the axum sub-router for the Raft HTTP transport, optionally gated on a
/// shared bearer `token`.
///
/// When `token` is `Some`, every `/append`, `/vote`, and `/snapshot` request
/// must carry a matching `Authorization: Bearer <token>` header (checked in
/// constant time); mismatches return `401` and — when `audit` is supplied —
/// record an [`AuditSinkKind::RemoteAuthFailed`] entry. When `token` is `None`
/// the routes are mounted without an auth layer (test / single-node use).
///
/// The daemon mounts this via
/// `.nest("/cluster/raft", raft_router_with_auth(node, Some(token), Some(audit)))`.
pub fn raft_router_with_auth(
    node: Arc<crate::election::RaftNode>,
    token: Option<String>,
    audit: Option<Arc<dyn AuditSink>>,
) -> Router {
    let mut router = Router::new()
        .route("/append", post(handle_append))
        .route("/vote", post(handle_vote))
        .route("/snapshot", post(handle_snapshot))
        .with_state(node);
    if let Some(tok) = token {
        let auth_state = RaftAuthState {
            token: Arc::new(tok),
            audit,
        };
        router = router.layer(from_fn_with_state(auth_state, raft_auth_middleware));
    }
    router
}

/// Reject Raft RPCs that don't present the cluster bearer token. Runs before
/// the append/vote/snapshot handlers when [`raft_router_with_auth`] was given a
/// token.
async fn raft_auth_middleware(
    State(auth): State<RaftAuthState>,
    req: Request,
    next: Next,
) -> axum::response::Response {
    let presented = bearer_from_headers(req.headers());
    let ok = presented
        .as_deref()
        .map(|t| constant_time_eq(t.as_bytes(), auth.token.as_bytes()))
        .unwrap_or(false);
    if ok {
        return next.run(req).await;
    }
    // Peer address is best-effort — recorded by `into_make_service_with_connect_info`.
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.to_string());
    if let Some(sink) = auth.audit.as_ref() {
        sink.record(
            AuditSinkKind::RemoteAuthFailed,
            None,
            None,
            json!({
                "peer": peer,
                "reason": "raft_auth",
                "surface": "cluster_raft",
            }),
        )
        .await;
    }
    warn!(peer = ?peer, "raft.http: rejected request without valid bearer token");
    (StatusCode::UNAUTHORIZED, "raft: bearer token required").into_response()
}

/// Extract the token from an `Authorization: Bearer <token>` header, if present.
fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let rest = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Constant-time byte-slice equality — avoids leaking token length/prefix via
/// timing. Differing lengths short-circuit (length is not itself secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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
    /// Shared cluster bearer token attached to every outbound RPC as
    /// `Authorization: Bearer <token>`. `None` = no auth header (test /
    /// single-node paths that mount [`raft_router`] without a token).
    token: Option<Arc<String>>,
}

impl RaftHttpFactory {
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Build a factory that attaches `Authorization: Bearer <token>` to every
    /// outbound append/vote/snapshot RPC. The token MUST match the one the
    /// peer daemons enforce via [`raft_router_with_auth`].
    pub fn with_token(token: impl Into<String>) -> Self {
        Self::build(Some(Arc::new(token.into())))
    }

    fn build(token: Option<Arc<String>>) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(DEFAULT_RPC_TIMEOUT)
            .timeout(DEFAULT_RPC_TIMEOUT)
            .user_agent(concat!("linpodx-raft/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            timeout: DEFAULT_RPC_TIMEOUT,
            token,
        }
    }

    pub fn with_client(http: reqwest::Client) -> Self {
        Self {
            http,
            timeout: DEFAULT_RPC_TIMEOUT,
            token: None,
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
            token: self.token.clone(),
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
    /// Shared cluster bearer token (see [`RaftHttpFactory::with_token`]).
    token: Option<Arc<String>>,
}

impl RaftHttpClient {
    fn url(&self, path: &str) -> String {
        format!("{}/cluster/raft/{path}", self.base_url)
    }

    /// Attach the cluster bearer token to a request builder when configured.
    fn authed(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.token.as_deref() {
            Some(tok) => rb.bearer_auth(tok),
            None => rb,
        }
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
            .authed(
                self.http
                    .post(self.url(path))
                    .timeout(self.timeout)
                    .json(body),
            )
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
            .authed(self.http.post(url).timeout(self.timeout).json(&rpc))
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
        // Plain `new()` factory carries no token.
        assert!(client.token.is_none());
    }

    #[tokio::test]
    async fn with_token_factory_propagates_token_to_client() {
        let mut factory = RaftHttpFactory::with_token("sekret");
        let node = BasicNode::new("127.0.0.1:9999".to_string());
        let client = factory.new_client(7, &node).await;
        assert_eq!(client.token.as_deref().map(String::as_str), Some("sekret"));
    }

    #[test]
    fn bearer_from_headers_extracts_and_rejects() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer hunter2".parse().unwrap());
        assert_eq!(bearer_from_headers(&h).as_deref(), Some("hunter2"));
        // Case-insensitive scheme, trims trailing space.
        let mut h = axum::http::HeaderMap::new();
        h.insert(AUTHORIZATION, "bearer  spaced ".parse().unwrap());
        assert_eq!(bearer_from_headers(&h).as_deref(), Some("spaced"));
        // Empty token / wrong scheme / missing header → None.
        let mut h = axum::http::HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(bearer_from_headers(&h).is_none());
        let mut h = axum::http::HeaderMap::new();
        h.insert(AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(bearer_from_headers(&h).is_none());
        assert!(bearer_from_headers(&axum::http::HeaderMap::new()).is_none());
    }

    #[test]
    fn constant_time_eq_matches_only_identical() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[tokio::test]
    async fn raft_router_auth_rejects_unauthenticated_and_accepts_valid_token() {
        use crate::election::{RaftNode, RaftStartConfig};

        let node = Arc::new(
            RaftNode::start(
                RaftStartConfig {
                    bootstrap_single_node: true,
                    ..Default::default()
                },
                None,
                None,
            )
            .await
            .expect("start"),
        );

        // Mount exactly as production does — nested under `/cluster/raft` — so the
        // test exercises the same paths the daemon exposes.
        let router = Router::new().nest(
            "/cluster/raft",
            raft_router_with_auth(Arc::clone(&node), Some("sekret".to_string()), None),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let serve = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        let client = reqwest::Client::new();
        let vote = VoteRequest::new(openraft::Vote::new(1, 1), None);
        let vote_url = format!("http://{addr}/cluster/raft/vote");
        let append_url = format!("http://{addr}/cluster/raft/append");

        // No Authorization header → 401 (vote).
        let resp = client
            .post(&vote_url)
            .json(&vote)
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 401, "unauthenticated vote must 401");

        // No Authorization header → 401 (append).
        let resp = client
            .post(&append_url)
            .body("{}")
            .header("content-type", "application/json")
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "unauthenticated append must 401"
        );

        // Wrong token → 401.
        let resp = client
            .post(&vote_url)
            .bearer_auth("nope")
            .json(&vote)
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 401, "wrong-token vote must 401");

        // Correct token → the request reaches the handler (single-node vote
        // succeeds → 200; never 401/404).
        let resp = client
            .post(&vote_url)
            .bearer_auth("sekret")
            .json(&vote)
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "authenticated vote round-trip must succeed"
        );

        serve.abort();
        Arc::try_unwrap(node)
            .unwrap_or_else(|n| (*n).clone())
            .shutdown()
            .await;
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
