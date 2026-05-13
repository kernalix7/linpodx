//! Daemon-side client for the privileged `linpodx-netfilter-helper` Unix socket.
//!
//! `EgressEnforcer` wraps the connection details and exposes:
//! * [`EgressEnforcer::is_helper_available`] — non-fatal probe used at container-start
//!   time so the daemon can decide whether to attempt L4 enforcement at all,
//! * [`EgressEnforcer::apply`] — sends an `Apply` request and reports back whether
//!   the helper accepted it. A missing helper resolves to `Ok(false)` (graceful
//!   degradation: the DNS-only filter remains in force) rather than failing the
//!   container lifecycle.

use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::network::EgressRule;
use linpodx_netfilter::wire::{HelperRequest, HelperResponse};
use linpodx_netfilter::{NetfilterError, Result, DEFAULT_SOCKET_PATH, SOCKET_ENV_VAR};
use linpodx_plugin::{NetworkDecision, NetworkTraceEvent, PluginRegistry};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tracing::{debug, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct EgressEnforcer {
    socket_path: PathBuf,
    /// Phase 13 / 14 — optional `network_trace` chain. Each rule is evaluated
    /// before being shipped to the helper. Decisions: `Allow` and `AuditOnly`
    /// keep the rule (audit-only differs only at the audit sink); `Deny` drops
    /// the rule from the outgoing allowlist, falling back to the helper's
    /// `policy drop` default. When no chain is wired, the rule list is passed
    /// through untouched.
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    /// Optional audit sink for `PluginNetworkTraceCalled` records.
    audit: Option<Arc<dyn AuditSink>>,
}

impl std::fmt::Debug for EgressEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressEnforcer")
            .field("socket_path", &self.socket_path)
            .field("plugin_registry", &self.plugin_registry.is_some())
            .field("audit", &self.audit.is_some())
            .finish()
    }
}

impl EgressEnforcer {
    /// Create an enforcer bound to an explicit helper socket path.
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            plugin_registry: None,
            audit: None,
        }
    }

    /// Build an enforcer using `LINPODX_NETFILTER_SOCKET` if set, else the compiled-in
    /// default (`/run/linpodx/netfilter.sock`).
    pub fn from_env() -> Self {
        let path = std::env::var(SOCKET_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));
        Self::new(path)
    }

    /// Phase 13 — wire an optional `network_trace` plugin chain plus audit sink.
    /// Returns `self` so it composes with `from_env` / `new`.
    pub fn with_plugins(
        mut self,
        plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> Self {
        self.plugin_registry = plugin_registry;
        self.audit = audit;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Try a `Ping` round-trip with a short timeout. Any error => `false`.
    pub async fn is_helper_available(&self) -> bool {
        match self.round_trip(HelperRequest::Ping).await {
            Ok(HelperResponse::Ok { .. }) => true,
            Ok(HelperResponse::Err { message }) => {
                warn!(error = %message, "helper ping returned err");
                false
            }
            Err(e) => {
                debug!(error = %e, "helper ping failed");
                false
            }
        }
    }

    /// Apply an L4 ruleset for `container_pid`. Returns `Ok((applied, count))` where
    /// `applied` is `true` if the helper acknowledged the request and `count` is the
    /// number of rules it actually loaded. Returns `Ok((false, 0))` when the helper
    /// is unavailable. Only true wire / protocol errors propagate as `Err`.
    ///
    /// Phase 14 — when a `network_trace` plugin chain returns `Deny` for a given
    /// allowlist row, that row is removed from the outgoing rule set *before* it
    /// reaches the helper. The helper's `output` chain default policy is `drop`,
    /// so removal is functionally equivalent to a per-rule drop. An
    /// `EgressDenyEnforced` audit record is emitted for each enforced denial.
    /// `AuditOnly`/`Allow` decisions still flow through with the original
    /// `PluginNetworkTraceCalled` audit hook.
    pub async fn apply(&self, container_pid: u32, rules: Vec<EgressRule>) -> Result<(bool, usize)> {
        let rules = self.filter_with_plugins(container_pid, rules).await;
        let total = rules.len();
        let req = HelperRequest::Apply {
            container_pid,
            rules,
        };
        match self.round_trip(req).await {
            Ok(HelperResponse::Ok { applied }) => Ok((true, applied)),
            Ok(HelperResponse::Err { message }) => Err(NetfilterError::HelperRejected(message)),
            Err(NetfilterError::HelperUnavailable(reason)) => {
                warn!(
                    reason,
                    socket = %self.socket_path.display(),
                    requested = total,
                    "egress helper unavailable; degrading to DNS-only filter"
                );
                Ok((false, 0))
            }
            Err(e) => Err(e),
        }
    }

    /// Phase 14 — run every `rule` through the optional `network_trace` plugin
    /// chain and decide what survives in the outgoing allowlist. Each call also
    /// emits the existing `PluginNetworkTraceCalled` audit record (decision
    /// included in the payload) so an operator can see what the chain returned.
    /// When the decision is `Deny`, the rule is dropped from the output and a
    /// dedicated `EgressDenyEnforced` audit record is appended; the rule's
    /// position is preserved in the audit payload via `original_index`.
    async fn filter_with_plugins(
        &self,
        container_pid: u32,
        rules: Vec<EgressRule>,
    ) -> Vec<EgressRule> {
        if self.plugin_registry.is_none() {
            return rules;
        }
        let mut decisions = Vec::with_capacity(rules.len());
        for rule in rules.iter() {
            let decision = run_network_trace_chain_audit(
                self.plugin_registry.clone(),
                rule_kind(rule),
                &rule.addr,
                rule.port,
            )
            .await;
            decisions.push(decision);
        }
        apply_chain_decisions(rules, &decisions, container_pid, self.audit.as_ref()).await
    }

    /// Clear the linpodx egress table for `container_pid`. Helper-unavailable is
    /// treated as Ok(false) for symmetry with `apply`.
    pub async fn clear(&self, container_pid: u32) -> Result<bool> {
        match self
            .round_trip(HelperRequest::Clear { container_pid })
            .await
        {
            Ok(HelperResponse::Ok { .. }) => Ok(true),
            Ok(HelperResponse::Err { message }) => Err(NetfilterError::HelperRejected(message)),
            Err(NetfilterError::HelperUnavailable(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn round_trip(&self, req: HelperRequest) -> Result<HelperResponse> {
        let stream =
            match tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket_path))
                .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    return Err(NetfilterError::HelperUnavailable(format!(
                        "connect {}: {e}",
                        self.socket_path.display()
                    )));
                }
                Err(_) => {
                    return Err(NetfilterError::HelperUnavailable(format!(
                        "connect {} timed out",
                        self.socket_path.display()
                    )));
                }
            };

        let (read_half, mut write_half) = stream.into_split();
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');
        write_half.write_all(&payload).await?;
        write_half.shutdown().await.ok();

        let mut lines = BufReader::new(read_half).lines();
        let line = match tokio::time::timeout(RESPONSE_TIMEOUT, lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                return Err(NetfilterError::MalformedResponse(
                    "helper closed connection before responding".into(),
                ));
            }
            Ok(Err(e)) => return Err(NetfilterError::Io(e)),
            Err(_) => {
                return Err(NetfilterError::HelperUnavailable(
                    "response timed out".into(),
                ));
            }
        };
        let resp: HelperResponse = serde_json::from_str(&line)
            .map_err(|e| NetfilterError::MalformedResponse(format!("{e}: {line}")))?;
        Ok(resp)
    }
}

impl Default for EgressEnforcer {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Map an `EgressRule` to the `kind` string the `network_trace` plugin chain expects.
fn rule_kind(rule: &EgressRule) -> &'static str {
    match rule.proto {
        linpodx_common::network::EgressProto::Tcp => "tcp_connect",
        linpodx_common::network::EgressProto::Udp => "udp_send",
        linpodx_common::network::EgressProto::Any => "any_connect",
    }
}

/// Pure-function applier: given parallel `rules` and `decisions`, return the rules that
/// survived the chain (plugin returned `Allow` or `AuditOnly`) and emit the matching
/// audit records when a sink is wired in. `Deny` removes the rule and emits
/// `EgressDenyEnforced` in addition to the standard `PluginNetworkTraceCalled` record.
///
/// Pulled out of [`EgressEnforcer::filter_with_plugins`] so unit tests can drive the
/// audit + filtering surface without standing up an actual `PluginRegistry`.
pub(crate) async fn apply_chain_decisions(
    rules: Vec<EgressRule>,
    decisions: &[NetworkDecision],
    container_pid: u32,
    audit: Option<&Arc<dyn AuditSink>>,
) -> Vec<EgressRule> {
    debug_assert_eq!(rules.len(), decisions.len());
    let mut kept = Vec::with_capacity(rules.len());
    for (idx, (rule, decision)) in rules.into_iter().zip(decisions.iter()).enumerate() {
        let kind = rule_kind(&rule);
        if let Some(sink) = audit {
            sink.record(
                AuditSinkKind::PluginNetworkTraceCalled,
                None,
                Some(format!("pid:{container_pid}")),
                serde_json::json!({
                    "kind": kind,
                    "host": rule.addr,
                    "port": rule.port,
                    "decision": format!("{:?}", decision),
                }),
            )
            .await;
        }
        if matches!(decision, NetworkDecision::Deny) {
            if let Some(sink) = audit {
                sink.record(
                    AuditSinkKind::EgressDenyEnforced,
                    None,
                    Some(format!("pid:{container_pid}")),
                    serde_json::json!({
                        "kind": kind,
                        "host": rule.addr,
                        "port": rule.port,
                        "original_index": idx,
                    }),
                )
                .await;
            }
            warn!(host = %rule.addr, port = ?rule.port, kind,
                "egress rule dropped by network_trace plugin chain");
            continue;
        }
        kept.push(rule);
    }
    kept
}

/// Mirror of the helper in `network_filter` — kept here to avoid a cross-module dep on
/// a private function. Empty registry / spawn failure resolve to `Allow` so an L4 apply
/// never fails because of a plugin runtime issue.
async fn run_network_trace_chain_audit(
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

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_netfilter::wire::HelperRequest;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Notify;

    /// Spin up a stub helper that replies to every request with `Ok { applied: probe }`.
    async fn stub_helper(socket: PathBuf, probe: usize) -> Arc<Notify> {
        let listener = UnixListener::bind(&socket).expect("bind stub");
        let stop = Arc::new(Notify::new());
        let stop_clone = Arc::clone(&stop);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_clone.notified() => break,
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _)) => {
                                tokio::spawn(handle_stub(stream, probe));
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
        stop
    }

    async fn handle_stub(stream: tokio::net::UnixStream, probe: usize) {
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let req: HelperRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let applied = match &req {
                HelperRequest::Apply { rules, .. } => rules.len(),
                _ => probe,
            };
            let resp = HelperResponse::Ok { applied };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            let _ = write_half.write_all(&bytes).await;
        }
    }

    #[tokio::test]
    async fn is_helper_available_false_when_socket_missing() {
        let dir = TempDir::new().unwrap();
        let enforcer = EgressEnforcer::new(dir.path().join("nope.sock"));
        assert!(!enforcer.is_helper_available().await);
    }

    #[tokio::test]
    async fn is_helper_available_true_against_stub() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("nf.sock");
        let _stop = stub_helper(sock.clone(), 7).await;
        let enforcer = EgressEnforcer::new(sock);
        assert!(enforcer.is_helper_available().await);
    }

    #[tokio::test]
    async fn apply_against_stub_returns_rule_count() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("nf.sock");
        let _stop = stub_helper(sock.clone(), 0).await;
        let enforcer = EgressEnforcer::new(sock);
        let rules = vec![EgressRule {
            proto: linpodx_common::network::EgressProto::Tcp,
            addr: "1.1.1.1".into(),
            port: Some(443),
            note: None,
        }];
        let (applied, count) = enforcer.apply(1234, rules).await.unwrap();
        assert!(applied);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn apply_returns_false_when_helper_missing() {
        let dir = TempDir::new().unwrap();
        let enforcer = EgressEnforcer::new(dir.path().join("missing.sock"));
        let (applied, count) = enforcer.apply(1, Vec::new()).await.unwrap();
        assert!(!applied);
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn run_network_trace_chain_audit_returns_allow_with_empty_registry() {
        let reg = PluginRegistry::new().expect("registry");
        let arc = Arc::new(RwLock::new(reg));
        let d = run_network_trace_chain_audit(Some(arc), "tcp_connect", "1.1.1.1", Some(443)).await;
        assert_eq!(d, NetworkDecision::Allow);
    }

    #[tokio::test]
    async fn run_network_trace_chain_audit_returns_allow_with_no_registry() {
        let d = run_network_trace_chain_audit(None, "tcp_connect", "1.1.1.1", Some(443)).await;
        assert_eq!(d, NetworkDecision::Allow);
    }

    #[tokio::test]
    async fn with_plugins_threads_through_apply_against_stub() {
        // Audit-only, so apply still succeeds with the stub helper count.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("nf.sock");
        let _stop = stub_helper(sock.clone(), 0).await;
        let reg = Arc::new(RwLock::new(PluginRegistry::new().expect("registry")));
        let enforcer = EgressEnforcer::new(sock).with_plugins(Some(reg), None);
        let rules = vec![EgressRule {
            proto: linpodx_common::network::EgressProto::Tcp,
            addr: "1.1.1.1".into(),
            port: Some(443),
            note: None,
        }];
        let (applied, count) = enforcer.apply(1234, rules).await.unwrap();
        assert!(applied);
        assert_eq!(count, 1);
    }

    // ---- Phase 14: chain-decision applier ----

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// Test-only audit sink that records every (kind, payload) tuple it sees so
    /// tests can assert which records were produced by the chain applier.
    #[derive(Default)]
    struct CountingSink {
        events: Mutex<Vec<(AuditSinkKind, serde_json::Value)>>,
    }

    impl CountingSink {
        fn snapshot(&self) -> Vec<(AuditSinkKind, serde_json::Value)> {
            self.events.lock().unwrap().clone()
        }

        fn count(&self, want: AuditSinkKind) -> usize {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| *k == want)
                .count()
        }
    }

    impl AuditSink for CountingSink {
        fn record(
            &self,
            kind: AuditSinkKind,
            _profile_name: Option<String>,
            _container_id: Option<String>,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.events.lock().unwrap().push((kind, payload));
            Box::pin(async {})
        }
    }

    fn rule(addr: &str, port: u16) -> EgressRule {
        EgressRule {
            proto: linpodx_common::network::EgressProto::Tcp,
            addr: addr.into(),
            port: Some(port),
            note: None,
        }
    }

    #[tokio::test]
    async fn apply_chain_decisions_audit_only_keeps_rule_no_deny_record() {
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let kept = apply_chain_decisions(
            vec![rule("1.1.1.1", 443)],
            &[NetworkDecision::AuditOnly],
            42,
            Some(&sink),
        )
        .await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].addr, "1.1.1.1");
        assert_eq!(counting.count(AuditSinkKind::PluginNetworkTraceCalled), 1);
        assert_eq!(counting.count(AuditSinkKind::EgressDenyEnforced), 0);
    }

    #[tokio::test]
    async fn apply_chain_decisions_deny_drops_rule_and_emits_enforced_record() {
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let kept = apply_chain_decisions(
            vec![rule("evil.example", 9000)],
            &[NetworkDecision::Deny],
            123,
            Some(&sink),
        )
        .await;
        assert!(kept.is_empty(), "Deny must drop the rule from the output");
        assert_eq!(counting.count(AuditSinkKind::PluginNetworkTraceCalled), 1);
        assert_eq!(counting.count(AuditSinkKind::EgressDenyEnforced), 1);
        let snap = counting.snapshot();
        let (_, deny_payload) = snap
            .iter()
            .find(|(k, _)| *k == AuditSinkKind::EgressDenyEnforced)
            .expect("deny enforced record present");
        assert_eq!(deny_payload["host"], "evil.example");
        assert_eq!(deny_payload["port"], 9000);
        assert_eq!(deny_payload["original_index"], 0);
    }

    #[tokio::test]
    async fn apply_chain_decisions_multiple_denies_remove_each_keeping_allows() {
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let rules = vec![
            rule("a.test", 1),
            rule("b.test", 2),
            rule("c.test", 3),
            rule("d.test", 4),
        ];
        let decisions = vec![
            NetworkDecision::Allow,
            NetworkDecision::Deny,
            NetworkDecision::Allow,
            NetworkDecision::Deny,
        ];
        let kept = apply_chain_decisions(rules, &decisions, 7, Some(&sink)).await;
        let kept_addrs: Vec<&str> = kept.iter().map(|r| r.addr.as_str()).collect();
        assert_eq!(kept_addrs, vec!["a.test", "c.test"]);
        assert_eq!(counting.count(AuditSinkKind::PluginNetworkTraceCalled), 4);
        assert_eq!(counting.count(AuditSinkKind::EgressDenyEnforced), 2);
        // Indices preserved against the *original* input order, not the surviving order.
        let denied_indices: Vec<i64> = counting
            .snapshot()
            .into_iter()
            .filter(|(k, _)| *k == AuditSinkKind::EgressDenyEnforced)
            .map(|(_, v)| v["original_index"].as_i64().unwrap())
            .collect();
        assert_eq!(denied_indices, vec![1, 3]);
    }

    #[tokio::test]
    async fn apply_chain_decisions_allow_only_no_deny_records_emitted() {
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let kept = apply_chain_decisions(
            vec![rule("ok.test", 80), rule("ok.test", 443)],
            &[NetworkDecision::Allow, NetworkDecision::Allow],
            1,
            Some(&sink),
        )
        .await;
        assert_eq!(kept.len(), 2);
        assert_eq!(counting.count(AuditSinkKind::PluginNetworkTraceCalled), 2);
        assert_eq!(counting.count(AuditSinkKind::EgressDenyEnforced), 0);
    }

    #[tokio::test]
    async fn apply_chain_decisions_with_no_audit_sink_still_filters_denied() {
        let kept = apply_chain_decisions(
            vec![rule("a", 1), rule("b", 2)],
            &[NetworkDecision::Deny, NetworkDecision::Allow],
            0,
            None,
        )
        .await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].addr, "b");
    }

    #[tokio::test]
    async fn from_env_uses_var_then_falls_back_to_default() {
        // Combined into one test so the two cases don't race on the shared env var when
        // cargo runs tests in parallel.
        let path = "/tmp/linpodx-test-from-env.sock";
        std::env::set_var(SOCKET_ENV_VAR, path);
        let from_env = EgressEnforcer::from_env();
        assert_eq!(from_env.socket_path(), Path::new(path));
        std::env::remove_var(SOCKET_ENV_VAR);
        let fallback = EgressEnforcer::from_env();
        assert_eq!(fallback.socket_path(), Path::new(DEFAULT_SOCKET_PATH));
    }
}
