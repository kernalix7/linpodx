//! Phase 7 — Remote daemon WebSocket listener.
//!
//! Exposes the same JSON-RPC dispatch surface that the Unix-socket server uses, but
//! over WebSocket so clients can reach the daemon across hosts (or containers, or
//! tunnels). v0.1 auth is a single static bearer token presented in the first text
//! frame after upgrade. Phase 8 layers optional TLS (server-only or full mTLS) on
//! top via [`TlsOptions`]; the bearer-token check still runs after a successful TLS
//! handshake (defence-in-depth).

use crate::dispatch::Dispatcher;
use crate::pin_store::{PinnedClientStore, TofuHandle};
use crate::web_ui;

// Re-export for the in-module mTLS acceptor at the bottom of this file.
pub(crate) use crate::pin_store::fingerprint_rustls_cert;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures::{SinkExt, StreamExt};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::ipc::{
    error_codes, JsonRpcVersion, ResponsePayload, RpcError, RpcRequest, RpcResponse,
};
use linpodx_runtime::PtyHandle;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// TLS / mTLS configuration for [`spawn`]. Cert + key are required; when `client_ca`
/// is also set, the listener requires clients to present a cert signed by one of the
/// CAs in that bundle (mTLS).
#[derive(Clone, Debug)]
pub struct TlsOptions {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub client_ca: Option<PathBuf>,
}

/// Snapshot of a running remote-listener instance.
pub struct RemoteState {
    pub addr: SocketAddr,
    pub token: String,
    pub sessions: Arc<AtomicU64>,
    pub dispatcher: Arc<Dispatcher>,
    pub audit: Arc<dyn AuditSink>,
    pub shutdown: CancellationToken,
    /// Whether TLS termination is enabled on this listener.
    pub tls_enabled: bool,
    /// Whether client cert verification (mTLS) is enabled on this listener.
    pub mtls_enabled: bool,
    /// Phase 15 Stream C — when true and `mtls_enabled` is also true, every
    /// upgrade requires the client cert's SHA-256 fingerprint to be present in
    /// [`PinnedClientStore`]. A miss returns 403 + audits `RemoteAuthFailed`.
    pub pin_clients_enabled: bool,
    /// Phase 15 Stream C — pin store consulted by the WebSocket handler when
    /// `pin_clients_enabled` is true. Cloned cheaply (`Arc` inside).
    pub pin_store: PinnedClientStore,
    /// Phase 16 Stream C — Trust-On-First-Use mode handle. Shared with the
    /// dispatcher so the `DaemonPinClientTofuEnable` arm and the WebSocket
    /// handler operate on the same enrolment counter under the same `Mutex`.
    /// When `Mutex<TofuMode>::should_enroll()` returns true on a pin
    /// mismatch, `ws_handler` calls `pin_store.insert(..)` + bumps the
    /// counter + audits `WsClientCertTofuEnrolled` instead of returning 403.
    pub tofu: TofuHandle,
    /// Map populated by the mTLS acceptor at handshake time and drained by the
    /// WebSocket handler at session-open time. Keyed by the client's `SocketAddr`
    /// (host+ephemeral port — unique per concurrent connection).
    pub mtls_peers: Arc<Mutex<HashMap<SocketAddr, MtlsPeerInfo>>>,
    /// Phase 12 — shared with [`Dispatcher`]. The `ContainerExecPty` arm inserts
    /// a `PtyHandle` keyed by `bridge_id`; the `/pty/<bridge_id>` WebSocket
    /// handler removes it on close (which drops the handle → kills the child).
    pub pty_handles: Arc<tokio::sync::Mutex<HashMap<String, PtyHandle>>>,
}

/// What we record about a client cert at handshake time.
#[derive(Clone, Debug)]
pub struct MtlsPeerInfo {
    pub cn: Option<String>,
    /// Phase 15 Stream C — lowercase hex SHA-256 of the leaf cert DER. The
    /// WebSocket handler matches this against [`PinnedClientStore`] when
    /// `pin_clients_enabled` is true; recorded in the audit payload regardless
    /// so operators can see which fingerprint connected even when pinning
    /// is off.
    pub fingerprint: Option<String>,
}

/// Handle returned by [`spawn`] — owns the cancellation token + the `serve` task so
/// the caller can stop the listener cleanly.
pub struct RemoteHandle {
    pub state: Arc<RemoteState>,
    pub task: JoinHandle<()>,
}

impl RemoteHandle {
    pub async fn shutdown(self) {
        self.state.shutdown.cancel();
        // Give the task a chance to drain; ignore join errors (cancellation aborts).
        let _ = self.task.await;
    }
}

/// Bind a TCP listener at `addr` and start serving WebSocket /ipc upgrades. When
/// `tls` is `Some`, the listener terminates TLS (and optionally enforces mTLS)
/// before passing the stream to axum.
///
/// The bind happens synchronously via `std::net::TcpListener` so the returned future
/// is `Send` even when invoked from a deeply-nested await chain (e.g. the
/// dispatcher's `RemoteListenStart` arm called from another remote session).
pub fn spawn(
    addr: SocketAddr,
    token: String,
    dispatcher: Arc<Dispatcher>,
    audit: Arc<dyn AuditSink>,
    tls: Option<TlsOptions>,
    pin_clients: bool,
) -> std::io::Result<RemoteHandle> {
    let std_listener = std::net::TcpListener::bind(addr)?;
    std_listener.set_nonblocking(true)?;
    let actual_addr = std_listener.local_addr().unwrap_or(addr);
    info!(addr = %actual_addr, tls = tls.is_some(), pin_clients, "remote WebSocket listener bound");

    let shutdown = CancellationToken::new();
    let mtls_peers = Arc::new(Mutex::new(HashMap::new()));
    let tls_enabled = tls.is_some();
    let mtls_enabled = tls.as_ref().is_some_and(|t| t.client_ca.is_some());
    let pin_clients_enabled = pin_clients && mtls_enabled;
    if pin_clients && !mtls_enabled {
        warn!("--pin-clients ignored because mTLS (--client-ca) is not enabled");
    }
    let pin_store = dispatcher.pin_store.clone();
    let pty_handles = Arc::clone(&dispatcher.pty_handles);
    let tofu = Arc::clone(&dispatcher.tofu);
    let state = Arc::new(RemoteState {
        addr: actual_addr,
        token,
        sessions: Arc::new(AtomicU64::new(0)),
        dispatcher,
        audit: Arc::clone(&audit),
        shutdown: shutdown.clone(),
        tls_enabled,
        mtls_enabled,
        pin_clients_enabled,
        pin_store,
        mtls_peers: Arc::clone(&mtls_peers),
        pty_handles,
        tofu,
    });

    let router = build_router(Arc::clone(&state));

    let task = match tls {
        None => {
            let listener = tokio::net::TcpListener::from_std(std_listener)?;
            let shutdown_for_serve = shutdown.clone();
            tokio::spawn(async move {
                let serve = axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(async move {
                    shutdown_for_serve.cancelled().await;
                });
                if let Err(e) = serve.await {
                    warn!(error = %e, "remote serve loop ended with error");
                } else {
                    debug!("remote serve loop ended cleanly");
                }
            })
        }
        Some(tls_opts) => {
            // Build the rustls ServerConfig synchronously so a config error fails
            // the spawn rather than crashing the background task.
            let server_config = build_server_config(&tls_opts).map_err(std::io::Error::other)?;
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
            let acceptor = mtls_acceptor::MtlsAcceptor::new(
                rustls_config,
                Arc::clone(&mtls_peers),
                Arc::clone(&audit),
                mtls_enabled,
            );
            let handle = axum_server::Handle::new();
            let handle_for_shutdown = handle.clone();
            let shutdown_for_serve = shutdown.clone();
            tokio::spawn(async move {
                shutdown_for_serve.cancelled().await;
                handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
            });
            tokio::spawn(async move {
                let res = axum_server::from_tcp(std_listener)
                    .acceptor(acceptor)
                    .handle(handle)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await;
                if let Err(e) = res {
                    warn!(error = %e, "remote TLS serve loop ended with error");
                } else {
                    debug!("remote TLS serve loop ended cleanly");
                }
            })
        }
    };

    Ok(RemoteHandle { state, task })
}

/// Build the axum router served by the remote listener.
///
/// Both the plaintext and TLS branches of [`spawn`] consume this so the
/// WebSocket `/ipc` upgrade, the Phase 8 Web UI JSON surface (`/api/v1/*`),
/// and the static assets at `/ui/*` are all reachable on the same port
/// regardless of transport.
pub(crate) fn build_router(state: Arc<RemoteState>) -> Router {
    let dispatcher = Arc::clone(&state.dispatcher);
    let token = Arc::new(state.token.clone());
    let audit = Arc::clone(&state.audit);
    let raft_node = state.dispatcher.raft.clone();
    let mut router = Router::new()
        .route("/ipc", get(ws_handler))
        .route("/pty/:bridge_id", get(pty_ws_handler))
        .with_state(Arc::clone(&state))
        .nest("/api/v1", web_ui::router(dispatcher, token, audit))
        .nest("/ui", web_ui::static_router());
    // Phase 14 Stream C — mount the Raft HTTP transport when leader-elect
    // is enabled. The router is only added when the dispatcher actually
    // holds a `RaftNode` so single-node deployments don't expose the
    // endpoints.
    if let Some(node) = raft_node {
        router = router.nest("/cluster/raft", linpodx_cluster::raft_router(node));
    }
    router
}

/// Optional `?token=<t>` query string used by browser clients that can't set
/// arbitrary WebSocket headers. Phase 10 added this as a second auth path
/// alongside the original first-frame `{"auth":"<t>"}` envelope.
///
/// Security note: query strings appear in TLS-terminating proxy access logs and
/// browser history. For untrusted networks pair this with mTLS rather than
/// relying on the bearer token alone.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct WsAuthQuery {
    #[serde(default)]
    pub token: Option<String>,
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    State(state): State<Arc<RemoteState>>,
    Query(q): Query<WsAuthQuery>,
) -> axum::response::Response {
    let query_token = q.token;
    // Phase 14 — Sec-WebSocket-Protocol bearer-token path. When the header
    // carries a matching `Bearer.<token>` (or `Bearer <token>`) entry, we
    // pre-validate it here so handle_socket can skip the in-band auth frame.
    // axum's `WebSocketUpgrade::protocols(["..."])` echoes the offered token
    // back in the response so the client knows the upgrade was accepted.
    let header_match = parse_bearer_subprotocol(&headers);
    let header_token_ok = match header_match.as_ref() {
        Some((_, token)) => constant_eq(token, &state.token),
        None => false,
    };
    let echoed_protocol = if header_token_ok {
        header_match.as_ref().map(|(p, _)| p.clone())
    } else {
        None
    };

    // Phase 15 Stream C — when --pin-clients is on, peek the fingerprint
    // recorded by the mTLS acceptor and reject the upgrade with HTTP 403 when
    // the cert is not in the pin store. We peek (vs remove) so handle_socket
    // can still drain it and emit the existing RemoteMtlsAccepted audit row.
    if state.pin_clients_enabled {
        let fingerprint = state
            .mtls_peers
            .lock()
            .ok()
            .and_then(|m| m.get(&peer).and_then(|info| info.fingerprint.clone()));
        let pin_ok = match fingerprint.as_deref() {
            Some(fp) => state.pin_store.contains(fp).await,
            None => false,
        };
        if pin_ok {
            if let Some(fp) = fingerprint.as_deref() {
                state
                    .audit
                    .record(
                        AuditSinkKind::WsClientCertPinned,
                        None,
                        None,
                        json!({
                            "peer": peer.to_string(),
                            "fingerprint": fp,
                        }),
                    )
                    .await;
            }
        } else if let Some(fp) = fingerprint.as_deref() {
            // Phase 16 Stream C — TOFU path. Snapshot the mode, decide
            // whether to enroll, then commit + audit on success. We hold the
            // sync `Mutex` only across the cheap snapshot/record operations
            // (no awaits) so concurrent upgrades don't deadlock. Async DB
            // I/O happens after the lock is released; the counter increment
            // is re-entered under the lock so the cap stays accurate.
            //
            // Phase 17 Stream C — the snapshot also drives time-based
            // auto-disable: if `max_age_secs` is configured and the window
            // has elapsed, we audit `TofuExpired`, flip `enabled` off
            // (`record_expiry`), and reject the upgrade as if pinning were
            // strict. The flip is one-shot per window so subsequent
            // upgrades hit the disabled path without re-auditing.
            let now_secs = chrono::Utc::now().timestamp();
            let (should_try_enroll, expired_anchor) = {
                let mut maybe_expired_at: Option<i64> = None;
                let mut allow = false;
                if let Ok(mut m) = state.tofu.lock() {
                    if m.is_expired_at(now_secs) {
                        maybe_expired_at = m.record_expiry();
                    } else {
                        allow = m.should_enroll_at(now_secs);
                    }
                }
                (allow, maybe_expired_at)
            };
            if let Some(anchor) = expired_anchor {
                state
                    .audit
                    .record(
                        AuditSinkKind::TofuExpired,
                        None,
                        None,
                        json!({
                            "peer": peer.to_string(),
                            "fingerprint": fp,
                            "enabled_at": anchor,
                            "expired_at": now_secs,
                        }),
                    )
                    .await;
            }
            if should_try_enroll {
                let inserted = state
                    .pin_store
                    .insert(fp, "tofu-auto")
                    .await
                    .unwrap_or(false);
                if inserted {
                    if let Ok(mut m) = state.tofu.lock() {
                        m.record_enrollment();
                    }
                    state
                        .audit
                        .record(
                            AuditSinkKind::WsClientCertTofuEnrolled,
                            None,
                            None,
                            json!({
                                "peer": peer.to_string(),
                                "fingerprint": fp,
                            }),
                        )
                        .await;
                }
                // Either we inserted, or the row was already there (race with
                // a parallel TOFU upgrade) — both cases mean the cert is now
                // pinned, so accept the upgrade.
            } else {
                audit_failure_pin(&state, peer, Some(fp)).await;
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    "client certificate is not pinned",
                )
                    .into_response();
            }
        } else {
            audit_failure_pin(&state, peer, None).await;
            return (
                axum::http::StatusCode::FORBIDDEN,
                "client certificate is not pinned",
            )
                .into_response();
        }
    }

    let upgrade = if let Some(p) = echoed_protocol.as_deref() {
        ws.protocols([p.to_string()])
    } else {
        ws
    };
    upgrade
        .on_upgrade(move |socket| handle_socket(socket, peer, state, query_token, header_token_ok))
        .into_response()
}

/// Phase 15 Stream C — record the audit entry for a pin-mismatch rejection.
/// Reuses `RemoteAuthFailed` so existing dashboards / alerting on remote-auth
/// failures pick it up without a schema bump.
async fn audit_failure_pin(state: &RemoteState, peer: SocketAddr, fingerprint: Option<&str>) {
    state
        .audit
        .record(
            AuditSinkKind::RemoteAuthFailed,
            None,
            None,
            json!({
                "peer": peer.to_string(),
                "reason": "pin_mismatch",
                "fingerprint": fingerprint,
            }),
        )
        .await;
    warn!(peer = %peer, fingerprint = ?fingerprint, "remote auth failed: pin_mismatch");
}

async fn handle_socket(
    socket: WebSocket,
    peer: SocketAddr,
    state: Arc<RemoteState>,
    query_token: Option<String>,
    header_token_ok: bool,
) {
    // If mTLS is enabled, the acceptor will have stashed peer info keyed by addr.
    // Drain it once and audit. Failure to find an entry while mTLS is on is unusual —
    // log it loudly but don't tear down the session (the TLS handshake itself
    // already verified the cert; CN is for audit, not auth).
    let mtls_peer = if state.mtls_enabled {
        let info = state
            .mtls_peers
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&peer));
        if let Some(info) = info.as_ref() {
            state
                .audit
                .record(
                    AuditSinkKind::RemoteMtlsAccepted,
                    None,
                    None,
                    json!({
                        "peer": peer.to_string(),
                        "cn": info.cn,
                    }),
                )
                .await;
        } else {
            warn!(peer = %peer, "mTLS enabled but no peer cert info recorded for this connection");
        }
        info
    } else {
        None
    };

    let (mut sender, mut receiver) = socket.split();

    // Phase 14 — Sec-WebSocket-Protocol header carrying `Bearer.<token>` is
    // preferred. ws_handler already validated and echoed it; we just record
    // the success here and skip the rest of the auth chain. CLI / scripts
    // can still fall through to the query-string or first-frame paths so
    // upgrades from older clients keep working unchanged.
    if header_token_ok {
        state
            .audit
            .record(
                AuditSinkKind::WsAuthSubprotocol,
                None,
                None,
                json!({
                    "peer": peer.to_string(),
                }),
            )
            .await;
    }

    // Phase 10: when the client passed `?token=<t>` and it matches, skip the
    // first-frame envelope check entirely. Browser clients can't set custom
    // WebSocket headers, so this is the only ergonomic path for the SPA.
    let query_token_ok = query_token
        .as_deref()
        .map(|t| constant_eq(t, &state.token))
        .unwrap_or(false);

    if !header_token_ok && !query_token_ok {
        // Step 1 — auth handshake. Expect a JSON object {"auth": "<token>"} as the
        // first text frame within ~10s. Anything else closes the socket and audits.
        let auth_msg =
            match tokio::time::timeout(std::time::Duration::from_secs(10), receiver.next()).await {
                Ok(Some(Ok(Message::Text(s)))) => s,
                _ => {
                    audit_failure(&state, peer, "no auth frame").await;
                    return;
                }
            };

        let presented_token: Option<String> = serde_json::from_str::<serde_json::Value>(&auth_msg)
            .ok()
            .and_then(|v| v.get("auth").and_then(|t| t.as_str()).map(str::to_string));

        let token_ok = presented_token
            .as_deref()
            .map(|t| constant_eq(t, &state.token))
            .unwrap_or(false);

        if !token_ok {
            audit_failure(&state, peer, "token mismatch").await;
            let _ = sender
                .send(Message::Text(
                    serde_json::to_string(&json!({
                        "error": {
                            "code": error_codes::INVALID_REQUEST,
                            "message": "auth failed",
                        },
                    }))
                    .unwrap_or_default(),
                ))
                .await;
            let _ = sender.send(Message::Close(None)).await;
            return;
        }
    }

    let session_seq = state.sessions.fetch_add(1, Ordering::SeqCst) + 1;
    state
        .audit
        .record(
            AuditSinkKind::RemoteSessionStarted,
            None,
            None,
            json!({
                "peer": peer.to_string(),
                "session_seq": session_seq,
                "tls": state.tls_enabled,
                "mtls_cn": mtls_peer.as_ref().and_then(|p| p.cn.clone()),
            }),
        )
        .await;
    info!(peer = %peer, session_seq, "remote WebSocket session opened");

    // Acknowledge auth. Clients can use the `since` field to confirm.
    let ack = json!({
        "auth": "ok",
        "since": chrono::Utc::now(),
    });
    if sender
        .send(Message::Text(
            serde_json::to_string(&ack).unwrap_or_default(),
        ))
        .await
        .is_err()
    {
        return;
    }

    // Step 2 — JSON-RPC NDJSON loop. Each text frame is one RpcRequest; we dispatch
    // and respond with one RpcResponse text frame. Close on any transport error.
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => {
                debug!(peer = %peer, "remote shutdown — closing session");
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
            msg = receiver.next() => {
                let raw = match msg {
                    Some(Ok(Message::Text(s))) => s,
                    Some(Ok(Message::Binary(_))) => {
                        // We only speak text NDJSON. Drop binary frames silently.
                        continue;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => continue, // Ping/Pong handled by axum
                    Some(Err(e)) => {
                        warn!(peer = %peer, error = %e, "remote socket read error");
                        break;
                    }
                };

                let resp = match serde_json::from_str::<RpcRequest>(&raw) {
                    Ok(req) => state.dispatcher.dispatch(req).await,
                    Err(e) => RpcResponse {
                        jsonrpc: JsonRpcVersion::V2,
                        id: None,
                        payload: ResponsePayload::Error {
                            error: RpcError {
                                code: error_codes::PARSE_ERROR,
                                message: format!("parse error: {e}"),
                                data: None,
                            },
                        },
                    },
                };

                let payload = match serde_json::to_string(&resp) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "remote response serialize failed");
                        continue;
                    }
                };
                if sender.send(Message::Text(payload)).await.is_err() {
                    debug!(peer = %peer, "remote send failed — closing");
                    break;
                }
            }
        }
    }

    debug!(peer = %peer, "remote session closed");
}

async fn audit_failure(state: &RemoteState, peer: SocketAddr, reason: &str) {
    state
        .audit
        .record(
            AuditSinkKind::RemoteAuthFailed,
            None,
            None,
            json!({
                "peer": peer.to_string(),
                "reason": reason,
            }),
        )
        .await;
    warn!(peer = %peer, reason, "remote auth failed");
}

/// Phase 14 — parse the `Sec-WebSocket-Protocol` header for a bearer token.
///
/// Returns the `(matched_protocol_token, extracted_token)` pair on the first
/// subprotocol entry whose payload starts with `Bearer.` or `Bearer ` (case
/// sensitive on the prefix; spaces are non-RFC but accepted for ergonomics).
/// Subprotocol entries are comma-separated and may also be split across
/// multiple `Sec-WebSocket-Protocol` header lines.
///
/// Returning the matched protocol verbatim lets the caller pass it back to
/// `WebSocketUpgrade::protocols(["..."])` — axum echoes exactly the offered
/// token back in its response, satisfying RFC 6455 §4.2.2.4.
pub fn parse_bearer_subprotocol(headers: &HeaderMap) -> Option<(String, String)> {
    for value in headers.get_all(axum::http::header::SEC_WEBSOCKET_PROTOCOL) {
        let raw = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for entry in raw.split(',') {
            let trimmed = entry.trim();
            if let Some(rest) = trimmed.strip_prefix("Bearer.") {
                if !rest.is_empty() {
                    return Some((trimmed.to_string(), rest.to_string()));
                }
            } else if let Some(rest) = trimmed.strip_prefix("Bearer ") {
                let token = rest.trim_start();
                if !token.is_empty() {
                    return Some((trimmed.to_string(), token.to_string()));
                }
            }
        }
    }
    None
}

/// Constant-time string equality — avoids leaking token length / prefix matches via
/// timing side channels. Both inputs are treated as opaque bytes.
pub fn constant_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..ab.len() {
        diff |= ab[i] ^ bb[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// TLS / mTLS support
// ---------------------------------------------------------------------------

/// Build a rustls `ServerConfig` from PEM cert/key files, with optional client cert
/// verification. Pinned to the `ring` provider via the workspace `rustls` feature
/// flags; we install a process-wide default provider once on first use.
pub fn build_server_config(opts: &TlsOptions) -> Result<rustls::ServerConfig, TlsConfigError> {
    install_default_crypto_provider();

    let cert_chain = load_certs(&opts.cert_path)?;
    let key = load_private_key(&opts.key_path)?;

    let builder = rustls::ServerConfig::builder();
    let builder = if let Some(ca_path) = &opts.client_ca {
        let ca_certs = load_certs(ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for c in ca_certs {
            roots
                .add(c)
                .map_err(|e| TlsConfigError::Other(format!("adding CA cert: {e}")))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| TlsConfigError::Other(format!("client verifier build: {e}")))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };

    builder
        .with_single_cert(cert_chain, key)
        .map_err(|e| TlsConfigError::Other(format!("with_single_cert: {e}")))
}

/// Errors returned by [`build_server_config`].
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("no certificate found in {0}")]
    NoCert(PathBuf),
    #[error("no private key found in {0}")]
    NoKey(PathBuf),
    #[error("{0}")]
    Other(String),
}

fn load_certs(
    path: &Path,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, TlsConfigError> {
    let pem = std::fs::read(path).map_err(|e| TlsConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = std::io::Cursor::new(pem);
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(TlsConfigError::NoCert(path.to_path_buf()));
    }
    Ok(certs)
}

fn load_private_key(
    path: &Path,
) -> Result<rustls_pki_types::PrivateKeyDer<'static>, TlsConfigError> {
    let pem = std::fs::read(path).map_err(|e| TlsConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = std::io::Cursor::new(pem);
    if let Some(key) = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsConfigError::Other(format!("parsing key: {e}")))?
    {
        return Ok(key);
    }
    Err(TlsConfigError::NoKey(path.to_path_buf()))
}

fn install_default_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Ignore the result — if another part of the process already installed a
        // provider, ours is a no-op.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Best-effort extraction of the Subject Common Name from a DER-encoded X.509 cert.
pub fn extract_cn(cert_der: &[u8]) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    cn
}

// ---------------------------------------------------------------------------
// Phase 12 — Interactive PTY WebSocket bridge
// ---------------------------------------------------------------------------

/// HTTP handler for `/pty/:bridge_id`. Looks up the [`PtyHandle`] previously
/// allocated by the `ContainerExecPty` JSON-RPC arm, and on success upgrades the
/// connection to a binary WebSocket that proxies stdin/stdout between the client
/// and the PTY master.
///
/// Auth: the same bearer token used for `/ipc` is enforced via the `?token=<t>`
/// query string. Browser/`tokio-tungstenite` clients can't easily set custom
/// headers on a WebSocket upgrade, so query-string auth is the only ergonomic
/// path. Token comparison is constant-time.
async fn pty_ws_handler(
    AxumPath(bridge_id): AxumPath<String>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(q): Query<WsAuthQuery>,
    State(state): State<Arc<RemoteState>>,
) -> impl IntoResponse {
    // Phase 14 — Sec-WebSocket-Protocol bearer-token path takes precedence over
    // the query-string `?token=` path; both are validated against the same
    // configured remote token. The header path emits a `WsAuthSubprotocol`
    // audit record so an operator can tell which auth path a client used.
    let header_match = parse_bearer_subprotocol(&headers);
    let header_token_ok = match header_match.as_ref() {
        Some((_, token)) => constant_eq(token, &state.token),
        None => false,
    };
    let query_token_ok = q
        .token
        .as_deref()
        .map(|t| constant_eq(t, &state.token))
        .unwrap_or(false);
    if !header_token_ok && !query_token_ok {
        warn!(bridge_id = %bridge_id, "pty WS: rejected unauthenticated request");
        return (axum::http::StatusCode::UNAUTHORIZED, "auth required").into_response();
    }
    if header_token_ok {
        state
            .audit
            .record(
                AuditSinkKind::WsAuthSubprotocol,
                None,
                None,
                json!({
                    "bridge_id": bridge_id,
                }),
            )
            .await;
    }
    // Existence check — without removing it (the WebSocket close path removes it).
    {
        let map = state.pty_handles.lock().await;
        if !map.contains_key(&bridge_id) {
            return (axum::http::StatusCode::NOT_FOUND, "no such bridge").into_response();
        }
    }
    let echoed_protocol = if header_token_ok {
        header_match.as_ref().map(|(p, _)| p.clone())
    } else {
        None
    };
    let upgrade = if let Some(p) = echoed_protocol.as_deref() {
        ws.protocols([p.to_string()])
    } else {
        ws
    };
    let state = Arc::clone(&state);
    upgrade
        .on_upgrade(move |socket| handle_pty_socket(socket, bridge_id, state))
        .into_response()
}

async fn handle_pty_socket(socket: WebSocket, bridge_id: String, state: Arc<RemoteState>) {
    // Take exclusive ownership of the handle. If a second client tries to attach
    // to the same bridge id, it will see 404 (the entry was removed). The handle
    // is re-inserted via guard pattern only if we successfully clone its I/O ends.
    let handle = {
        let mut map = state.pty_handles.lock().await;
        match map.remove(&bridge_id) {
            Some(h) => h,
            None => {
                warn!(bridge_id = %bridge_id, "pty WS: handle vanished between routing and upgrade");
                return;
            }
        }
    };

    // Clone blocking I/O ends (portable-pty exposes std::io traits, not async).
    // `take_writer` consumes the writer slot from the master — only one writer per
    // session. `try_clone_reader` allows multiple read clones, but we only need one.
    let writer: Box<dyn std::io::Write + Send> = match handle.master.take_writer() {
        Ok(w) => w,
        Err(e) => {
            warn!(bridge_id = %bridge_id, error = %e, "pty WS: take_writer failed");
            audit_pty_closed(&state, &bridge_id, "take_writer_failed").await;
            return;
        }
    };
    let reader: Box<dyn std::io::Read + Send> = match handle.master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            warn!(bridge_id = %bridge_id, error = %e, "pty WS: clone reader failed");
            audit_pty_closed(&state, &bridge_id, "clone_reader_failed").await;
            return;
        }
    };

    // Park the handle in a Tokio mutex behind the bridge id again so the Drop runs
    // when *either* the WS or the child closes — whichever comes first triggers
    // cleanup below.
    let parked = Arc::new(tokio::sync::Mutex::new(Some(handle)));

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Channel: pty reader thread → axum WebSocket sender task. Bounded so a stuck
    // client backpressures the pty rather than ballooning memory.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // pty → ws: blocking read on master.read in a spawn_blocking, forward bytes via tx.
    let bridge_id_for_reader = bridge_id.clone();
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF — child closed
                Ok(n) => {
                    let chunk = buf[..n].to_vec();
                    if tx.blocking_send(chunk).is_err() {
                        // ws side hung up
                        break;
                    }
                }
                Err(e) => {
                    debug!(bridge_id = %bridge_id_for_reader, error = %e, "pty read error — ending");
                    break;
                }
            }
        }
        // Closing tx signals the forwarder loop below to exit.
    });

    // ws ← pty: drain rx into ws sender as binary frames.
    let bridge_id_for_forward = bridge_id.clone();
    let forward_task = tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            if ws_sender.send(Message::Binary(chunk)).await.is_err() {
                debug!(bridge_id = %bridge_id_for_forward, "pty WS sender failed — ending");
                break;
            }
        }
        let _ = ws_sender.send(Message::Close(None)).await;
    });

    // ws → pty: read frames from client, write bytes into the master writer.
    // The writer is also blocking I/O, so we hop onto spawn_blocking for each
    // batch. Inbound traffic from a human keyboard is tiny so this is fine.
    let writer = Arc::new(std::sync::Mutex::new(writer));
    let bridge_id_for_input = bridge_id.clone();
    let input_writer = Arc::clone(&writer);
    let input_task = tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            let frame = match msg {
                Ok(Message::Binary(data)) => data,
                Ok(Message::Text(s)) => s.into_bytes(),
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
            };
            let writer_clone = Arc::clone(&input_writer);
            let bid = bridge_id_for_input.clone();
            let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                use std::io::Write;
                let mut w = writer_clone
                    .lock()
                    .map_err(|_| std::io::Error::other("writer lock poisoned"))?;
                w.write_all(&frame)?;
                w.flush()?;
                Ok(())
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    debug!(bridge_id = %bid, error = %e, "pty input write failed — ending");
                    break;
                }
                Err(e) => {
                    warn!(bridge_id = %bid, error = %e, "pty input write task join failed");
                    break;
                }
            }
        }
    });

    // Wait for either side to terminate, then tear everything down.
    tokio::select! {
        _ = forward_task => {}
        _ = input_task => {}
        _ = state.shutdown.cancelled() => {
            debug!(bridge_id = %bridge_id, "pty WS: daemon shutdown — closing");
        }
    }

    // Drop the handle (best-effort kills the child + closes master), then audit.
    {
        let mut slot = parked.lock().await;
        let _ = slot.take();
    }
    // The reader task may still be blocked on master.read; closing the master
    // unblocks it via EOF. We just join it best-effort.
    let _ = reader_task.await;

    audit_pty_closed(&state, &bridge_id, "client_or_child_closed").await;
}

async fn audit_pty_closed(state: &RemoteState, bridge_id: &str, reason: &str) {
    state
        .audit
        .record(
            AuditSinkKind::ContainerExecPtyClosed,
            None,
            None,
            json!({
                "bridge_id": bridge_id,
                "reason": reason,
            }),
        )
        .await;
}

mod mtls_acceptor {
    //! Wraps [`axum_server::tls_rustls::RustlsAcceptor`] so we can peek at the
    //! peer certificate after the TLS handshake completes and stash the resulting
    //! [`MtlsPeerInfo`] keyed by client `SocketAddr` for the WebSocket handler to
    //! pick up later.

    use super::{extract_cn, MtlsPeerInfo};
    use axum_server::accept::Accept;
    use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
    use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
    use serde_json::json;
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpStream;
    use tracing::warn;

    #[derive(Clone)]
    pub struct MtlsAcceptor {
        inner: RustlsAcceptor,
        peers: Arc<Mutex<HashMap<SocketAddr, MtlsPeerInfo>>>,
        audit: Arc<dyn AuditSink>,
        require_mtls: bool,
    }

    impl MtlsAcceptor {
        pub fn new(
            cfg: RustlsConfig,
            peers: Arc<Mutex<HashMap<SocketAddr, MtlsPeerInfo>>>,
            audit: Arc<dyn AuditSink>,
            require_mtls: bool,
        ) -> Self {
            Self {
                inner: RustlsAcceptor::new(cfg),
                peers,
                audit,
                require_mtls,
            }
        }
    }

    impl<S> Accept<TcpStream, S> for MtlsAcceptor
    where
        S: Send + 'static,
    {
        type Stream = <RustlsAcceptor as Accept<TcpStream, S>>::Stream;
        type Service = S;
        type Future =
            Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

        fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
            let peer_addr = stream.peer_addr().ok();
            let peers = Arc::clone(&self.peers);
            let audit = Arc::clone(&self.audit);
            let require_mtls = self.require_mtls;
            let inner_fut = self.inner.accept(stream, service);
            Box::pin(async move {
                match inner_fut.await {
                    Ok((tls_stream, svc)) => {
                        if require_mtls {
                            let (cn, fingerprint) = {
                                let server_conn = tls_stream.get_ref().1;
                                let chain = server_conn.peer_certificates();
                                let leaf = chain.and_then(|certs| certs.first());
                                let cn = leaf.and_then(|der| extract_cn(der.as_ref()));
                                let fp = leaf.map(super::fingerprint_rustls_cert);
                                (cn, fp)
                            };
                            if let Some(addr) = peer_addr {
                                if let Ok(mut m) = peers.lock() {
                                    m.insert(addr, MtlsPeerInfo { cn, fingerprint });
                                }
                            }
                        }
                        Ok((tls_stream, svc))
                    }
                    Err(e) => {
                        let peer_str = peer_addr
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "?".into());
                        let reason = e.to_string();
                        if require_mtls {
                            let audit_clone = Arc::clone(&audit);
                            tokio::spawn(async move {
                                audit_clone
                                    .record(
                                        AuditSinkKind::RemoteMtlsRejected,
                                        None,
                                        None,
                                        json!({
                                            "peer": peer_str,
                                            "reason": reason,
                                        }),
                                    )
                                    .await;
                            });
                        }
                        warn!(error = %e, "TLS handshake failed");
                        Err(e)
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_eq_matches_only_identical() {
        assert!(constant_eq("abc", "abc"));
        assert!(!constant_eq("abc", "abd"));
        assert!(!constant_eq("abc", "abcd"));
        assert!(!constant_eq("", "x"));
        assert!(constant_eq("", ""));
    }

    #[test]
    fn auth_frame_parses_token() {
        let raw = r#"{"auth":"hunter2"}"#;
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        let token = parsed
            .get("auth")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        assert_eq!(token, Some("hunter2".into()));
    }

    #[test]
    fn ws_auth_query_extracts_token_via_serde_json() {
        // Round-trip a JSON object through the same serde::Deserialize impl axum's
        // Query extractor uses (form-urlencoded → struct). We use JSON here so the
        // test stays self-contained without pulling in serde_urlencoded.
        let q: WsAuthQuery = serde_json::from_str(r#"{"token":"hunter2"}"#).unwrap();
        assert_eq!(q.token.as_deref(), Some("hunter2"));
        let empty: WsAuthQuery = serde_json::from_str("{}").unwrap();
        assert!(empty.token.is_none());
    }

    #[test]
    fn auth_frame_rejects_missing_field() {
        let raw = r#"{"foo":"bar"}"#;
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        let token = parsed.get("auth").and_then(|v| v.as_str());
        assert!(token.is_none());
    }

    fn write_pem(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn gen_self_signed_pair() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    #[test]
    fn build_server_config_loads_pem_pair() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = gen_self_signed_pair();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert_pem);
        let key_path = write_pem(dir.path(), "key.pem", &key_pem);
        let opts = TlsOptions {
            cert_path,
            key_path,
            client_ca: None,
        };
        let _cfg = build_server_config(&opts).expect("server config builds");
    }

    #[test]
    fn build_server_config_with_client_ca_enables_mtls() {
        let dir = tempfile::tempdir().unwrap();
        let (server_cert_pem, server_key_pem) = gen_self_signed_pair();
        let (ca_pem, _) = gen_self_signed_pair();
        let cert_path = write_pem(dir.path(), "scert.pem", &server_cert_pem);
        let key_path = write_pem(dir.path(), "skey.pem", &server_key_pem);
        let ca_path = write_pem(dir.path(), "ca.pem", &ca_pem);
        let opts = TlsOptions {
            cert_path,
            key_path,
            client_ca: Some(ca_path),
        };
        let _cfg = build_server_config(&opts).expect("mTLS server config builds");
    }

    #[test]
    fn build_server_config_rejects_missing_files() {
        let opts = TlsOptions {
            cert_path: PathBuf::from("/nonexistent/no.pem"),
            key_path: PathBuf::from("/nonexistent/no.key"),
            client_ca: None,
        };
        let err = build_server_config(&opts).unwrap_err();
        assert!(matches!(err, TlsConfigError::Io { .. }));
    }

    #[test]
    fn extract_cn_returns_none_for_garbage() {
        assert!(extract_cn(&[0u8; 4]).is_none());
    }

    // ---- Phase 14: Sec-WebSocket-Protocol bearer-token parsing ----

    fn make_headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(
                axum::http::header::SEC_WEBSOCKET_PROTOCOL,
                v.parse().expect("valid header value"),
            );
        }
        h
    }

    #[test]
    fn parse_bearer_subprotocol_extracts_dotted_token() {
        let h = make_headers(&["Bearer.hunter2"]);
        let got = parse_bearer_subprotocol(&h).expect("matched");
        assert_eq!(got.0, "Bearer.hunter2");
        assert_eq!(got.1, "hunter2");
    }

    #[test]
    fn parse_bearer_subprotocol_extracts_space_separated_token() {
        let h = make_headers(&["Bearer hunter2"]);
        let got = parse_bearer_subprotocol(&h).expect("matched");
        assert_eq!(got.0, "Bearer hunter2");
        assert_eq!(got.1, "hunter2");
    }

    #[test]
    fn parse_bearer_subprotocol_picks_first_when_multiple() {
        let h = make_headers(&["json, Bearer.aaa, Bearer.bbb"]);
        let got = parse_bearer_subprotocol(&h).expect("matched");
        assert_eq!(got.1, "aaa");
    }

    #[test]
    fn parse_bearer_subprotocol_handles_multi_header_lines() {
        let h = make_headers(&["json", "Bearer.zzz"]);
        let got = parse_bearer_subprotocol(&h).expect("matched");
        assert_eq!(got.1, "zzz");
    }

    #[test]
    fn parse_bearer_subprotocol_none_when_missing() {
        let h = HeaderMap::new();
        assert!(parse_bearer_subprotocol(&h).is_none());
    }

    #[test]
    fn parse_bearer_subprotocol_none_when_other_protocols_only() {
        let h = make_headers(&["graphql-ws, json"]);
        assert!(parse_bearer_subprotocol(&h).is_none());
    }

    #[test]
    fn parse_bearer_subprotocol_rejects_empty_token() {
        let h = make_headers(&["Bearer."]);
        assert!(parse_bearer_subprotocol(&h).is_none());
        let h = make_headers(&["Bearer "]);
        assert!(parse_bearer_subprotocol(&h).is_none());
    }

    #[test]
    fn header_path_constant_eq_validates_token_match() {
        // Mirror the daemon-side check that gates header_token_ok in
        // ws_handler / pty_ws_handler. A matching token leaves header_token_ok
        // true; a mismatch flips back to false so the auth chain falls through.
        let h = make_headers(&["Bearer.hunter2"]);
        let parsed = parse_bearer_subprotocol(&h).expect("matched");
        assert!(constant_eq(&parsed.1, "hunter2"));
        assert!(!constant_eq(&parsed.1, "hunter3"));
    }

    #[test]
    fn header_path_falls_back_to_query_when_no_subprotocol_offered() {
        // Simulate a client that didn't send Sec-WebSocket-Protocol — the
        // header parse returns None, so handle_socket would proceed to check
        // query_token / first-frame envelope. We assert that fallback path is
        // observable: header_token_ok false, but a matching query token still
        // authorises the session.
        let h = HeaderMap::new();
        assert!(parse_bearer_subprotocol(&h).is_none());
        let query_token = Some("hunter2".to_string());
        let ok = query_token
            .as_deref()
            .map(|t| constant_eq(t, "hunter2"))
            .unwrap_or(false);
        assert!(ok, "query-string fallback must still authorise");
    }

    #[test]
    fn header_path_and_query_path_both_reject_wrong_tokens() {
        // Both auth paths fail when the offered token doesn't match — this is
        // the precondition under which ws_handler closes the connection with
        // "auth failed" and audit_failure records a RemoteAuthFailed entry.
        let h = make_headers(&["Bearer.WRONG"]);
        let parsed = parse_bearer_subprotocol(&h).expect("matched");
        assert!(!constant_eq(&parsed.1, "hunter2"));
        let query_token = Some("ALSO_WRONG".to_string());
        let ok = query_token
            .as_deref()
            .map(|t| constant_eq(t, "hunter2"))
            .unwrap_or(false);
        assert!(!ok, "neither auth path should authorise");
    }
}
