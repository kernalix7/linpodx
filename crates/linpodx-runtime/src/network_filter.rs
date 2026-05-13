//! DNS-based egress allowlist filter.
//!
//! Spawns a tiny in-process DNS server bound to a local UDP+TCP socket. Queries are matched
//! against an allowlist (suffix-based, dot-aware). Misses are answered with `NXDOMAIN` so
//! containerized processes cannot resolve disallowed hosts and therefore cannot connect.
//!
//! The allowlist match is dot-aware: `"openai.com"` matches both `openai.com` itself and
//! `api.openai.com`, but does NOT match `evil-openai.com`.
//!
//! Allowed queries are forwarded to an upstream resolver (defaults to system resolv.conf
//! via [`hickory_resolver::TokioAsyncResolver::tokio_from_system_conf`]).
//!
//! Drop the [`FilterHandle`] to stop the server.

use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{LowerName, Name, RData, Record};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture,
};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_plugin::{NetworkDecision, NetworkTraceEvent, PluginRegistry};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Default TCP timeout for the DNS server's stream connections.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// Suffix-match a hostname against an allowlist entry. Dot-aware so a partial substring
/// match (`"foo-openai.com"` against `"openai.com"`) does NOT count. Both inputs are
/// expected to already be lowercase / FQDN-stripped.
pub fn host_matches_allow(host: &str, allow: &str) -> bool {
    if host == allow {
        return true;
    }
    if !host.ends_with(allow) {
        return false;
    }
    // Ensure the boundary is on a label, e.g. ".openai.com" not "Xopenai.com".
    let cut = host.len() - allow.len();
    cut > 0 && host.as_bytes()[cut - 1] == b'.'
}

/// Returns `true` if `host` matches any entry in `allowlist`.
pub fn is_allowed(host: &str, allowlist: &[String]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    for raw in allowlist {
        let a = raw.trim_end_matches('.').to_ascii_lowercase();
        if a.is_empty() {
            continue;
        }
        if host_matches_allow(&h, &a) {
            return true;
        }
    }
    false
}

/// Per-server state shared with the [`RequestHandler`].
struct FilterHandler {
    allowlist: Vec<String>,
    upstream: Option<TokioAsyncResolver>,
    /// Optional plugin chain. When present, every DNS query first runs through
    /// `evaluate_network_trace` — `Deny` overrides the allowlist (returns NXDOMAIN),
    /// `AuditOnly`/`Allow` fall through to the existing allowlist gate. Each call also
    /// emits a best-effort `PluginNetworkTraceCalled` audit entry when an `audit` sink
    /// is configured.
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    audit: Option<Arc<dyn AuditSink>>,
}

#[async_trait::async_trait]
impl RequestHandler for FilterHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let header = request.header();
        let mut response_header = Header::response_from_request(header);

        // Reject anything that isn't a normal query: not an update, not a response.
        if request.message_type() != MessageType::Query || request.op_code() != OpCode::Query {
            response_header.set_response_code(ResponseCode::NotImp);
            return send_empty(&mut response_handle, request, response_header).await;
        }

        let query = request.query();
        let host_name: LowerName = query.name().clone();
        let host_str = host_name.to_string();

        // Phase 13: optional `network_trace` plugin chain. Runs *before* the allowlist
        // so a plugin Deny is authoritative. Allow / AuditOnly fall through; AuditOnly
        // only differs from Allow at the audit-sink level.
        let plugin_decision =
            run_network_trace_chain(self.plugin_registry.clone(), "dns_query", &host_str, None)
                .await;
        if let Some(audit) = self.audit.as_ref() {
            audit
                .record(
                    AuditSinkKind::PluginNetworkTraceCalled,
                    None,
                    None,
                    serde_json::json!({
                        "kind": "dns_query",
                        "host": host_str,
                        "decision": format!("{:?}", plugin_decision),
                    }),
                )
                .await;
        }
        if matches!(plugin_decision, NetworkDecision::Deny) {
            warn!(host = %host_str, "network_trace plugin denied egress");
            response_header.set_response_code(ResponseCode::NXDomain);
            return send_empty(&mut response_handle, request, response_header).await;
        }

        if !is_allowed(&host_str, &self.allowlist) {
            warn!(host = %host_str, "egress DNS filter blocked");
            response_header.set_response_code(ResponseCode::NXDomain);
            return send_empty(&mut response_handle, request, response_header).await;
        }

        debug!(host = %host_str, "egress DNS filter allowed");

        // Allowed — forward upstream if a resolver is configured. Without one we SERVFAIL
        // because we have no answers to give; this is intentional for the "deny by default,
        // explicit allow + explicit upstream" deployment shape.
        let Some(resolver) = &self.upstream else {
            response_header.set_response_code(ResponseCode::ServFail);
            return send_empty(&mut response_handle, request, response_header).await;
        };

        let qtype = query.query_type();
        let lookup_name: Name = host_name.into();
        let answers: Vec<Record> = match resolver.lookup(lookup_name, qtype).await {
            Ok(lookup) => lookup
                .record_iter()
                .filter_map(|r| {
                    let rdata: RData = r.data()?.clone();
                    Some(Record::from_rdata(r.name().clone(), r.ttl(), rdata))
                })
                .collect(),
            Err(e) => {
                warn!(host = %host_str, error = %e, "upstream resolver lookup failed");
                response_header.set_response_code(ResponseCode::ServFail);
                return send_empty(&mut response_handle, request, response_header).await;
            }
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let msg = builder.build(response_header, answers.iter(), &[], &[], &[]);
        match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(e) => {
                warn!(error = %e, "failed sending DNS answer");
                make_serve_failed()
            }
        }
    }
}

async fn send_empty<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    header: Header,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    match handle.send_response(builder.build_no_records(header)).await {
        Ok(info) => info,
        Err(e) => {
            warn!(error = %e, "failed sending DNS response");
            make_serve_failed()
        }
    }
}

/// Build a `ResponseInfo` carrying `ResponseCode::ServFail` since the upstream associated
/// constructor is crate-private.
fn make_serve_failed() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}

/// Handle to a running DNS filter. Drop to stop.
pub struct FilterHandle {
    addr: SocketAddr,
    task: Option<JoinHandle<()>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FilterHandle {
    /// Local socket the DNS server is listening on (UDP + TCP share the same port).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for FilterHandle {
    fn drop(&mut self) {
        // Ignore send errors — receiver may have already shut down on its own.
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let prev = std::mem::replace(&mut self.shutdown, tx);
        let _ = prev.send(());
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Run the optional `network_trace` plugin chain inside `spawn_blocking` so the wasmtime
/// store stays off the async executor. Empty registry / spawn failure resolve to `Allow`
/// — egress decisions must never block on a plugin runtime issue.
async fn run_network_trace_chain(
    registry: Option<Arc<RwLock<PluginRegistry>>>,
    kind: &str,
    host: &str,
    port: Option<u16>,
) -> NetworkDecision {
    let Some(reg) = registry else {
        return NetworkDecision::Allow;
    };
    let event = NetworkTraceEvent {
        kind: kind.to_string(),
        host: host.to_string(),
        port,
    };
    match tokio::task::spawn_blocking(move || {
        let mut guard = reg.blocking_write();
        guard.evaluate_network_trace(&event)
    })
    .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "network_trace task join failed; treating as Allow");
            NetworkDecision::Allow
        }
    }
}

/// Start an egress-filter DNS server on a 127.0.0.1 ephemeral port.
///
/// `allowlist` entries are dot-aware suffixes (e.g. `["openai.com", "example.com"]`).
/// `upstream` selects the upstream resolver: `None` uses the system `/etc/resolv.conf`.
pub async fn start(
    allowlist: Vec<String>,
    upstream: Option<SocketAddr>,
) -> std::io::Result<FilterHandle> {
    start_on(allowlist, upstream, "127.0.0.1:0".parse().unwrap()).await
}

/// Variant of [`start`] that wires an optional `network_trace` plugin chain plus an
/// audit sink. Behavior is identical to [`start`] when both are `None`.
pub async fn start_with_plugins(
    allowlist: Vec<String>,
    upstream: Option<SocketAddr>,
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    audit: Option<Arc<dyn AuditSink>>,
) -> std::io::Result<FilterHandle> {
    start_on_with_plugins(
        allowlist,
        upstream,
        "127.0.0.1:0".parse().unwrap(),
        plugin_registry,
        audit,
    )
    .await
}

/// Variant of [`start`] that lets the caller pick the bind address (useful for tests
/// asserting a particular interface).
pub async fn start_on(
    allowlist: Vec<String>,
    upstream: Option<SocketAddr>,
    bind: SocketAddr,
) -> std::io::Result<FilterHandle> {
    start_on_with_plugins(allowlist, upstream, bind, None, None).await
}

/// Full-fat variant — explicit bind, optional plugin chain, optional audit sink. The
/// plain `start` / `start_on` callers route through here with `None`/`None`.
pub async fn start_on_with_plugins(
    allowlist: Vec<String>,
    upstream: Option<SocketAddr>,
    bind: SocketAddr,
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    audit: Option<Arc<dyn AuditSink>>,
) -> std::io::Result<FilterHandle> {
    let resolver = match upstream {
        Some(addr) => {
            let mut cfg = ResolverConfig::new();
            cfg.add_name_server(hickory_resolver::config::NameServerConfig {
                socket_addr: addr,
                protocol: hickory_resolver::config::Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
            Some(TokioAsyncResolver::tokio(cfg, ResolverOpts::default()))
        }
        None => match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(error = %e, "could not load system resolver; allowed queries will SERVFAIL");
                None
            }
        },
    };

    let udp = UdpSocket::bind(bind).await?;
    let tcp = TcpListener::bind(bind).await?;
    let local = udp.local_addr()?;
    info!(addr = %local, allowlist_len = allowlist.len(), "egress DNS filter started");

    let handler = FilterHandler {
        allowlist,
        upstream: resolver,
        plugin_registry,
        audit,
    };
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp);
    server.register_listener(tcp, TCP_TIMEOUT);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let server = Arc::new(tokio::sync::Mutex::new(server));
        tokio::select! {
            _ = shutdown_rx => {
                let mut guard = server.lock().await;
                if let Err(e) = guard.shutdown_gracefully().await {
                    warn!(error = %e, "DNS filter shutdown error");
                }
            }
            res = async {
                let mut guard = server.lock().await;
                guard.block_until_done().await
            } => {
                if let Err(e) = res {
                    warn!(error = %e, "DNS filter exited with error");
                }
            }
        }
    });

    Ok(FilterHandle {
        addr: local,
        task: Some(task),
        shutdown: shutdown_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_allowed() {
        assert!(is_allowed("openai.com", &["openai.com".into()]));
    }

    #[test]
    fn subdomain_allowed() {
        assert!(is_allowed("api.openai.com", &["openai.com".into()]));
        assert!(is_allowed("api.openai.com.", &["openai.com".into()]));
    }

    #[test]
    fn deep_subdomain_allowed() {
        assert!(is_allowed("v1.api.eu.openai.com", &["openai.com".into()]));
    }

    #[test]
    fn case_insensitive() {
        assert!(is_allowed("API.OpenAI.COM", &["openai.com".into()]));
    }

    #[test]
    fn partial_match_blocked() {
        assert!(!is_allowed("evil-openai.com", &["openai.com".into()]));
        assert!(!is_allowed("openai.com.evil.io", &["openai.com".into()]));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        assert!(!is_allowed("openai.com", &[]));
    }

    #[test]
    fn empty_allow_entry_is_ignored() {
        assert!(!is_allowed("openai.com", &["".into()]));
    }

    #[test]
    fn unrelated_blocked() {
        assert!(!is_allowed(
            "blocked.example.com",
            &["allowed.example.com".into(), "github.com".into()]
        ));
    }

    #[test]
    fn one_of_many_allowed() {
        let allow = vec!["openai.com".into(), "example.com".into()];
        assert!(is_allowed("api.example.com", &allow));
        assert!(is_allowed("api.openai.com", &allow));
        assert!(!is_allowed("api.evil.com", &allow));
    }

    #[test]
    fn host_matches_allow_boundary_check() {
        assert!(host_matches_allow("a.b.com", "b.com"));
        assert!(!host_matches_allow("ab.com", "b.com"));
        assert!(host_matches_allow("b.com", "b.com"));
    }

    #[tokio::test]
    async fn start_binds_to_loopback_and_drop_stops() {
        let handle = start(vec!["example.com".into()], None)
            .await
            .expect("start filter");
        let addr = handle.local_addr();
        assert!(addr.ip().is_loopback());
        assert!(addr.port() != 0);
        // Drop should stop without panicking.
        drop(handle);
    }

    #[tokio::test]
    async fn run_network_trace_chain_with_no_registry_returns_allow() {
        let d = run_network_trace_chain(None, "dns_query", "example.com", None).await;
        assert_eq!(d, NetworkDecision::Allow);
    }

    #[tokio::test]
    async fn run_network_trace_chain_with_empty_registry_returns_allow() {
        let reg = PluginRegistry::new().expect("registry");
        let arc = Arc::new(RwLock::new(reg));
        let d = run_network_trace_chain(Some(arc), "dns_query", "example.com", None).await;
        assert_eq!(d, NetworkDecision::Allow);
    }

    #[tokio::test]
    #[ignore]
    async fn end_to_end_blocks_disallowed_query() {
        // This test actually issues a UDP DNS query. Marked `#[ignore]` to keep CI fast and
        // because some hermetic CI sandboxes don't allow loopback UDP binds.
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;
        use tokio::net::UdpSocket;

        let handle = start(vec!["allowed.test".into()], None)
            .await
            .expect("start");
        let addr = handle.local_addr();

        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(
            Name::from_str("blocked.test.").unwrap(),
            RecordType::A,
        ));

        let bytes = msg.to_vec().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&bytes, addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv");
        let resp = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        drop(handle);
    }
}
