//! MCP host-stdio bridge.
//!
//! `BridgeRegistry::start` spawns a host MCP server process plus a `podman exec -i`
//! shell inside the target container, then wires stdout/stdin pairs in both
//! directions. Each line is best-effort JSON-parsed; if a `method` field is found
//! the bridge audits the call. Phase 2D shipped a static allowlist; Phase 2E adds a
//! per-method [`McpPolicyRule`] store evaluated through [`PolicyEngine`] plus an
//! optional [`ApprovalGateway`] for `Prompt` decisions.
//!
//! ## Fail-closed on unparseable frames
//!
//! When a policy engine is configured (the policy store is non-empty), an inbound line
//! that [`McpMessage::parse`] cannot recognize is **denied**, not forwarded. Otherwise a
//! parser-differential payload — one this crate's parser rejects but the downstream MCP
//! server still understands — would silently bypass every `Deny` rule. The legacy static
//! allowlist path (which forwards method-less/malformed lines as audit-only) runs **only
//! when no policy is configured at all**, preserving backward compatibility for pre-2E
//! deployments. There is deliberately no env-var escape hatch: if a profile genuinely
//! needs to pass unparseable frames it must opt in explicitly via the policy schema
//! (default deny), which lives in `linpodx-common` and is not wired here.
//!
//! Denied unparseable frames are audited as [`AuditSinkKind::McpToolDenied`] with a
//! distinct `decision` field of `"unparseable_denied"` (the shared audit-kind enum is
//! owned by `linpodx-common`, so the distinguishing marker rides in the payload).

use crate::policy::PolicyEngine;
use crate::protocol::{self, McpMessage};
use anyhow::Context;
use chrono::{DateTime, Utc};
use linpodx_common::approval::{
    ApprovalCategory, ApprovalGateway, ApprovalOutcome, ApprovalRequest,
};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::ipc::{McpCapabilities, McpPolicyDecision, McpPolicyRule};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, instrument, warn};

const MCP_PAYLOAD_TRUNCATE: usize = 8 * 1024;
const DIRECTION_HOST_TO_CONTAINER: &str = "host_to_container";
const DIRECTION_CONTAINER_TO_HOST: &str = "container_to_host";
/// Default profile name reported in approval requests when the bridge is started without
/// a sandbox profile context. Kept short so listeners can render it clearly.
const APPROVAL_PROFILE_NAME: &str = "mcp-bridge";
/// Same default the daemon uses elsewhere — long enough that a human can answer, short
/// enough that an unattended bridge doesn't wedge a tool call indefinitely.
const APPROVAL_TIMEOUT_SECS: u64 = 30;

/// Stable identifier for a running bridge.
pub type BridgeId = String;

/// Shared, mutable per-process MCP policy table. The daemon loads the table from SQLite
/// on startup and replaces it on `mcp_policy_set`. Bridges read it on every message.
pub type PolicyStore = Arc<RwLock<Vec<McpPolicyRule>>>;

/// Construct an empty `PolicyStore`. Callers populate it at daemon boot from
/// `mcp_policy::McpPolicyStore::load_all`.
pub fn empty_policy_store() -> PolicyStore {
    Arc::new(RwLock::new(Vec::new()))
}

/// Registry of live bridges. Owns the audit sink + policy store + (optional) gateway
/// and the id-allocator counter.
pub struct BridgeRegistry {
    sink: Arc<dyn AuditSink>,
    policy_store: PolicyStore,
    gateway: Option<Arc<dyn ApprovalGateway>>,
    bridges: Mutex<HashMap<BridgeId, Arc<Bridge>>>,
    next_id: AtomicU64,
}

impl BridgeRegistry {
    /// Backward-compatible constructor — no policy store, no gateway. Bridges fall back
    /// to the static `allowlist` behavior and forward unmatched messages.
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self::with_policy_and_gateway(sink, empty_policy_store(), None)
    }

    /// Full constructor used by the daemon. The `policy_store` is kept so subsequent
    /// `mcp_policy_set` calls can mutate it in place and every running bridge sees the
    /// new rules on the next message.
    pub fn with_policy_and_gateway(
        sink: Arc<dyn AuditSink>,
        policy_store: PolicyStore,
        gateway: Option<Arc<dyn ApprovalGateway>>,
    ) -> Self {
        Self {
            sink,
            policy_store,
            gateway,
            bridges: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// Hand out a clone of the policy store so admin code (`mcp_policy_set` arm in the
    /// dispatcher) can rewrite the in-memory snapshot in lockstep with the DB.
    pub fn policy_store(&self) -> PolicyStore {
        Arc::clone(&self.policy_store)
    }

    /// Spawn a new bridge. The `podman_bin` is invoked as
    /// `<podman_bin> exec -i <container_id> /bin/sh -c "cat"` for v0.1 — the user is
    /// expected to wire a real MCP server inside the container in subsequent
    /// versions.
    #[instrument(skip(self))]
    pub async fn start(
        &self,
        podman_bin: String,
        container_id: String,
        host_command: String,
        host_args: Vec<String>,
        allowlist: Vec<String>,
    ) -> anyhow::Result<BridgeStartHandle> {
        let bridge_id = self.allocate_id();
        let started_at = Utc::now();

        let mut host_cmd = Command::new(&host_command);
        host_cmd
            .args(&host_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut host_child = host_cmd
            .spawn()
            .with_context(|| format!("spawn host command '{host_command}'"))?;

        let mut container_cmd = Command::new(&podman_bin);
        container_cmd
            .arg("exec")
            .arg("-i")
            .arg(&container_id)
            .arg("/bin/sh")
            .arg("-c")
            .arg("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut container_child = container_cmd.spawn().with_context(|| {
            format!("spawn 'podman exec -i {container_id}' (binary: {podman_bin})")
        })?;

        let host_stdin = host_child
            .stdin
            .take()
            .context("host stdin missing after spawn")?;
        let host_stdout = host_child
            .stdout
            .take()
            .context("host stdout missing after spawn")?;
        let container_stdin = container_child
            .stdin
            .take()
            .context("container stdin missing after spawn")?;
        let container_stdout = container_child
            .stdout
            .take()
            .context("container stdout missing after spawn")?;

        let messages = Arc::new(AtomicU64::new(0));
        let allowlist_set: Arc<HashSet<String>> = Arc::new(allowlist.into_iter().collect());
        let capabilities = Arc::new(RwLock::new(None));
        let subscriptions = Arc::new(RwLock::new(HashSet::new()));
        let pending_initialize_ids = Arc::new(Mutex::new(HashSet::<i64>::new()));

        let bridge = Arc::new(Bridge {
            id: bridge_id.clone(),
            container_id: container_id.clone(),
            host_command: host_command.clone(),
            started_at,
            messages_seen: Arc::clone(&messages),
            host_child: Mutex::new(Some(host_child)),
            container_child: Mutex::new(Some(container_child)),
            capabilities: Arc::clone(&capabilities),
            subscriptions: Arc::clone(&subscriptions),
        });

        let ctx_h = PumpContext {
            sink: Arc::clone(&self.sink),
            allowlist: Arc::clone(&allowlist_set),
            policy_store: Arc::clone(&self.policy_store),
            gateway: self.gateway.clone(),
            messages: Arc::clone(&messages),
            container_id: container_id.clone(),
            bridge_id: bridge_id.clone(),
            capabilities: Arc::clone(&capabilities),
            subscriptions: Arc::clone(&subscriptions),
            pending_initialize_ids: Arc::clone(&pending_initialize_ids),
        };
        let ctx_c = ctx_h.clone();

        // host -> container direction
        tokio::spawn(async move {
            pump(
                BufReader::new(host_stdout),
                container_stdin,
                DIRECTION_HOST_TO_CONTAINER,
                ctx_h,
            )
            .await;
        });

        // container -> host direction
        tokio::spawn(async move {
            pump(
                BufReader::new(container_stdout),
                host_stdin,
                DIRECTION_CONTAINER_TO_HOST,
                ctx_c,
            )
            .await;
        });

        {
            let mut guard = self.bridges.lock().await;
            guard.insert(bridge_id.clone(), Arc::clone(&bridge));
        }
        self.sink
            .record(
                AuditSinkKind::McpBridgeStarted,
                None,
                Some(container_id.clone()),
                serde_json::json!({
                    "bridge_id": bridge_id,
                    "host_command": host_command,
                    "container_id": container_id,
                }),
            )
            .await;
        info!(bridge_id = %bridge_id, container = %container_id, "MCP bridge started");
        Ok(BridgeStartHandle { bridge_id })
    }

    /// Stop a running bridge. Returns `true` if it was found.
    #[instrument(skip(self))]
    pub async fn stop(&self, bridge_id: &str) -> anyhow::Result<bool> {
        let bridge = {
            let mut guard = self.bridges.lock().await;
            guard.remove(bridge_id)
        };
        let Some(bridge) = bridge else {
            return Ok(false);
        };
        if let Some(mut child) = bridge.host_child.lock().await.take() {
            if let Err(e) = child.start_kill() {
                warn!(error = %e, "host child kill failed");
            }
        }
        if let Some(mut child) = bridge.container_child.lock().await.take() {
            if let Err(e) = child.start_kill() {
                warn!(error = %e, "container child kill failed");
            }
        }
        self.sink
            .record(
                AuditSinkKind::McpBridgeStopped,
                None,
                Some(bridge.container_id.clone()),
                serde_json::json!({"bridge_id": bridge.id}),
            )
            .await;
        info!(bridge_id = %bridge_id, "MCP bridge stopped");
        Ok(true)
    }

    /// Snapshot of currently-running bridges. If `bridge_id` is set, return only that
    /// bridge (or empty Vec if missing).
    pub async fn status(&self, bridge_id: Option<&str>) -> Vec<BridgeStatusEntry> {
        let guard = self.bridges.lock().await;
        let iter: Box<dyn Iterator<Item = &Arc<Bridge>>> = match bridge_id {
            Some(want) => Box::new(guard.values().filter(move |b| b.id == want)),
            None => Box::new(guard.values()),
        };
        iter.map(|b| BridgeStatusEntry {
            bridge_id: b.id.clone(),
            container_id: b.container_id.clone(),
            host_command: b.host_command.clone(),
            started_at: b.started_at,
            messages_seen: b.messages_seen.load(Ordering::Relaxed),
        })
        .collect()
    }

    /// Phase 2F: snapshot of the bridge's negotiated capabilities. Returns `None` if the
    /// bridge id is unknown; returns `Some(default)` if known but the initialize handshake
    /// has not completed yet.
    pub async fn capabilities(&self, bridge_id: &str) -> Option<McpCapabilities> {
        let bridge = {
            let guard = self.bridges.lock().await;
            guard.get(bridge_id).cloned()
        }?;
        let caps = bridge.capabilities.read().await.clone();
        Some(caps.unwrap_or_default())
    }

    /// Phase 2F: snapshot of the URIs the host has subscribed to on this bridge.
    /// Returns `None` if the bridge id is unknown.
    pub async fn subscriptions(&self, bridge_id: &str) -> Option<Vec<String>> {
        let bridge = {
            let guard = self.bridges.lock().await;
            guard.get(bridge_id).cloned()
        }?;
        let mut subs: Vec<String> = bridge.subscriptions.read().await.iter().cloned().collect();
        subs.sort();
        Some(subs)
    }

    fn allocate_id(&self) -> BridgeId {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        format!("br-{now}-{n}")
    }
}

fn new_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("mcp-{now}-{n}")
}

/// Returned from `BridgeRegistry::start` so callers can echo the id back to clients.
#[derive(Debug, Clone)]
pub struct BridgeStartHandle {
    pub bridge_id: BridgeId,
}

/// One running bridge.
pub struct Bridge {
    pub id: BridgeId,
    pub container_id: String,
    pub host_command: String,
    pub started_at: DateTime<Utc>,
    pub messages_seen: Arc<AtomicU64>,
    host_child: Mutex<Option<Child>>,
    container_child: Mutex<Option<Child>>,
    /// Phase 2F: capability cache populated when the host's first `initialize` request
    /// receives a matching response from the container side. Shared with the pump
    /// contexts via `Arc` so the registry's accessors observe live state.
    capabilities: Arc<RwLock<Option<McpCapabilities>>>,
    /// Phase 2F: per-bridge URI subscription set. Updated by host→container
    /// `resources/subscribe` / `resources/unsubscribe`; consulted on
    /// container→host `notifications/resources/updated`.
    subscriptions: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct BridgeStatusEntry {
    pub bridge_id: BridgeId,
    pub container_id: String,
    pub host_command: String,
    pub started_at: DateTime<Utc>,
    pub messages_seen: u64,
}

/// Best-effort JSON-RPC method extraction from one stdio line. Kept for backward
/// compatibility with callers that only need the raw method string (audit-only path).
pub fn extract_method(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    value
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}

/// Decide whether a method is allowed via the legacy allowlist.
/// - empty allowlist  → audit-only (always allowed)
/// - non-empty + miss → denied
/// - non-empty + hit  → allowed
pub fn check_allowlist(allowlist: &HashSet<String>, method: Option<&str>) -> AllowlistDecision {
    if allowlist.is_empty() {
        return AllowlistDecision::AuditOnly;
    }
    match method {
        Some(m) if allowlist.contains(m) => AllowlistDecision::Allowed,
        Some(_) => AllowlistDecision::Denied,
        // Methodless lines (notifications without `method`, malformed JSON) are audit-only.
        None => AllowlistDecision::AuditOnly,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistDecision {
    Allowed,
    Denied,
    AuditOnly,
}

impl AllowlistDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::AuditOnly => "audit_only",
        }
    }
}

/// Per-pump state, cloned once per direction. Cheap to clone — everything is `Arc`.
#[derive(Clone)]
struct PumpContext {
    sink: Arc<dyn AuditSink>,
    allowlist: Arc<HashSet<String>>,
    policy_store: PolicyStore,
    gateway: Option<Arc<dyn ApprovalGateway>>,
    messages: Arc<AtomicU64>,
    container_id: String,
    bridge_id: BridgeId,
    /// Phase 2F: shared capability cache, populated when the matching `initialize`
    /// response arrives. Reads are cheap; writes happen at most once per bridge
    /// (and only on the container→host direction).
    capabilities: Arc<RwLock<Option<McpCapabilities>>>,
    /// Phase 2F: per-bridge subscription set, mutated by the host→container direction
    /// (subscribe / unsubscribe) and read by the container→host direction
    /// (resources/updated filtering).
    subscriptions: Arc<RwLock<HashSet<String>>>,
    /// Phase 6 (Stream C): set of ids for pending host→container `initialize`
    /// requests. The host side inserts ids as Initialize requests pass through;
    /// the container side removes them when a matching JSON-RPC response is observed
    /// and uses the response payload to populate `capabilities`. A set lets the bridge
    /// handle out-of-order or concurrent re-initialization handshakes without losing
    /// either response.
    pending_initialize_ids: Arc<Mutex<HashSet<i64>>>,
}

async fn pump<R, W>(
    mut reader: BufReader<R>,
    mut writer: W,
    direction: &'static str,
    ctx: PumpContext,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf).await {
            Ok(0) => {
                debug!(direction, bridge_id = %ctx.bridge_id, "stdio EOF");
                break;
            }
            Ok(_) => {
                ctx.messages.fetch_add(1, Ordering::Relaxed);
                let trimmed = buf.trim_end_matches('\n').to_string();

                let parsed = McpMessage::parse(&trimmed);
                let payload = if trimmed.len() > MCP_PAYLOAD_TRUNCATE {
                    trimmed[..MCP_PAYLOAD_TRUNCATE].to_string()
                } else {
                    trimmed.clone()
                };

                // Phase 2F: side-effect handling (subscribe/unsubscribe/list_changed/
                // resources_updated/initialize-response). Returns Some(decision) when
                // the variant fully owns the audit + forward decision; otherwise None
                // means "fall through to the existing policy/allowlist path".
                if let Some(decision) =
                    handle_phase2f(&ctx, direction, parsed.as_ref(), &trimmed).await
                {
                    if !record_and_forward(&ctx, &mut writer, direction, &payload, &buf, decision)
                        .await
                    {
                        break;
                    }
                    continue;
                }

                // Hold the read lock once: evaluate the rules and capture whether the
                // store has any entries (the legacy fallback only fires on empty stores).
                let (policy_decision, policy_active) = {
                    let rules = ctx.policy_store.read().await;
                    let dec = parsed
                        .as_ref()
                        .map(|msg| PolicyEngine::evaluate(&rules, msg));
                    (dec, !rules.is_empty())
                };

                // Resolve the final decision. `policy_decision` is `Some` exactly when the
                // message parsed, so the three arms below are: (1) policy configured and
                // message parsed → policy engine; (2) policy configured but the frame is
                // unparseable → fail *closed* (deny), never fall through to the allowlist,
                // otherwise a parser-differential payload bypasses every Deny rule; (3) no
                // policy configured → legacy static allowlist, keeping pre-2E deployments
                // working.
                let final_decision = match (policy_active, policy_decision) {
                    (true, Some(dec)) => {
                        let method = parsed.as_ref().map(|m| m.method_str().to_string());
                        let tool = parsed
                            .as_ref()
                            .and_then(|m| m.tool_name().map(String::from));
                        resolve_via_policy(&ctx, dec, method, tool, parsed.as_ref()).await
                    }
                    (true, None) => {
                        warn!(
                            direction,
                            bridge_id = %ctx.bridge_id,
                            "unparseable frame denied under active policy (fail-closed)"
                        );
                        Decision {
                            forward: false,
                            audit_kind: AuditSinkKind::McpToolDenied,
                            decision_str: "unparseable_denied",
                            method: None,
                        }
                    }
                    (false, _) => {
                        let method = parsed
                            .as_ref()
                            .map(|m| m.method_str().to_string())
                            .or_else(|| extract_method(&trimmed));
                        let allowlist_dec = check_allowlist(&ctx.allowlist, method.as_deref());
                        Decision {
                            forward: matches!(
                                allowlist_dec,
                                AllowlistDecision::Allowed | AllowlistDecision::AuditOnly
                            ),
                            audit_kind: match allowlist_dec {
                                AllowlistDecision::Denied => AuditSinkKind::McpToolDenied,
                                _ => AuditSinkKind::McpToolCalled,
                            },
                            decision_str: allowlist_dec.as_str(),
                            method,
                        }
                    }
                };

                if !record_and_forward(&ctx, &mut writer, direction, &payload, &buf, final_decision)
                    .await
                {
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, direction, bridge_id = %ctx.bridge_id, "read error; pump exiting");
                break;
            }
        }
    }
}

/// Audit + (optionally) forward one line. Returns `false` on a fatal write error so the
/// caller can break out of the read loop.
async fn record_and_forward<W>(
    ctx: &PumpContext,
    writer: &mut W,
    direction: &'static str,
    payload: &str,
    raw_line: &str,
    decision: Decision,
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    ctx.sink
        .record(
            decision.audit_kind,
            None,
            Some(ctx.container_id.clone()),
            serde_json::json!({
                "bridge_id": ctx.bridge_id,
                "direction": direction,
                "method": decision.method,
                "decision": decision.decision_str,
                "payload": payload,
            }),
        )
        .await;

    if !decision.forward {
        debug!(
            direction,
            method = ?decision.method,
            bridge_id = %ctx.bridge_id,
            decision = decision.decision_str,
            "dropping message"
        );
        return true;
    }

    if let Err(e) = writer.write_all(raw_line.as_bytes()).await {
        warn!(error = %e, direction, bridge_id = %ctx.bridge_id, "write error; pump exiting");
        return false;
    }
    if let Err(e) = writer.flush().await {
        warn!(error = %e, direction, bridge_id = %ctx.bridge_id, "flush error; pump exiting");
        return false;
    }
    true
}

/// Direction-aware handling of Phase 2F variants. Returns:
/// - `Some(Decision)` — variant fully handled (subscription mutated, capability cache
///   filled, etc.); caller emits audit + forwards/drops per the returned `Decision`.
/// - `None` — line is not a Phase 2F concern; caller proceeds with the existing
///   policy/allowlist resolution path.
async fn handle_phase2f(
    ctx: &PumpContext,
    direction: &'static str,
    parsed: Option<&McpMessage>,
    raw: &str,
) -> Option<Decision> {
    if direction == DIRECTION_HOST_TO_CONTAINER {
        // Host-side: capture every Initialize id we see (concurrent / sequential
        // re-handshakes both work), track subscriptions.
        match parsed {
            Some(McpMessage::Initialize { .. }) => {
                if let Some(id) = extract_id(raw) {
                    let mut guard = ctx.pending_initialize_ids.lock().await;
                    guard.insert(id);
                }
                None
            }
            Some(McpMessage::ResourcesSubscribe { uri }) => {
                {
                    let mut guard = ctx.subscriptions.write().await;
                    guard.insert(uri.clone());
                }
                Some(Decision {
                    forward: true,
                    audit_kind: AuditSinkKind::McpResourceSubscribed,
                    decision_str: "subscribed",
                    method: Some(
                        McpMessage::ResourcesSubscribe { uri: uri.clone() }
                            .method_str()
                            .to_string(),
                    ),
                })
            }
            Some(McpMessage::ResourcesUnsubscribe { uri }) => {
                {
                    let mut guard = ctx.subscriptions.write().await;
                    guard.remove(uri);
                }
                Some(Decision {
                    forward: true,
                    audit_kind: AuditSinkKind::McpResourceUnsubscribed,
                    decision_str: "unsubscribed",
                    method: Some(
                        McpMessage::ResourcesUnsubscribe { uri: uri.clone() }
                            .method_str()
                            .to_string(),
                    ),
                })
            }
            _ => None,
        }
    } else {
        // Container-side: resources/updated filter, list-changed pass-through, capture
        // the initialize response.
        match parsed {
            Some(McpMessage::ResourcesUpdated { uri }) => {
                let subscribed = {
                    let guard = ctx.subscriptions.read().await;
                    guard.contains(uri)
                };
                if subscribed {
                    Some(Decision {
                        forward: true,
                        audit_kind: AuditSinkKind::McpResourceUpdated,
                        decision_str: "forwarded_subscribed",
                        method: Some(
                            McpMessage::ResourcesUpdated { uri: uri.clone() }
                                .method_str()
                                .to_string(),
                        ),
                    })
                } else {
                    Some(Decision {
                        forward: false,
                        audit_kind: AuditSinkKind::McpResourceUpdated,
                        decision_str: "dropped_unsubscribed",
                        method: Some(
                            McpMessage::ResourcesUpdated { uri: uri.clone() }
                                .method_str()
                                .to_string(),
                        ),
                    })
                }
            }
            Some(McpMessage::ToolsListChanged)
            | Some(McpMessage::ResourcesListChanged)
            | Some(McpMessage::PromptsListChanged) => {
                let method = parsed.map(|m| m.method_str().to_string());
                Some(Decision {
                    forward: true,
                    audit_kind: AuditSinkKind::McpListChanged,
                    decision_str: "list_changed",
                    method,
                })
            }
            _ => {
                // Non-`method` JSON: try to match an initialize response. We snapshot
                // the pending-id set, find the first one whose response payload
                // matches this line, and remove it. Last-write-wins on capabilities so
                // a client that re-initializes always sees the most recent reply.
                let pending: Vec<i64> = {
                    let guard = ctx.pending_initialize_ids.lock().await;
                    guard.iter().copied().collect()
                };
                for id in pending {
                    if let Some(caps) = protocol::parse_initialize_response(raw, id) {
                        {
                            let mut guard = ctx.capabilities.write().await;
                            *guard = Some(caps);
                        }
                        {
                            let mut guard = ctx.pending_initialize_ids.lock().await;
                            guard.remove(&id);
                        }
                        return Some(Decision {
                            forward: true,
                            audit_kind: AuditSinkKind::McpListChanged,
                            decision_str: "initialize_complete",
                            method: Some("initialize/response".to_string()),
                        });
                    }
                }
                None
            }
        }
    }
}

/// Extract the JSON-RPC `id` field as i64 from a raw line, if present.
fn extract_id(line: &str) -> Option<i64> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    value.get("id").and_then(|v| v.as_i64())
}

/// Resolved verdict for one stdio line.
struct Decision {
    forward: bool,
    audit_kind: AuditSinkKind,
    decision_str: &'static str,
    method: Option<String>,
}

async fn resolve_via_policy(
    ctx: &PumpContext,
    decision: McpPolicyDecision,
    method: Option<String>,
    tool: Option<String>,
    parsed: Option<&McpMessage>,
) -> Decision {
    match decision {
        McpPolicyDecision::AutoAllow => Decision {
            forward: true,
            audit_kind: AuditSinkKind::McpToolCalled,
            decision_str: "auto_allow",
            method,
        },
        McpPolicyDecision::AuditOnly => Decision {
            forward: true,
            audit_kind: AuditSinkKind::McpToolCalled,
            decision_str: "audit_only",
            method,
        },
        McpPolicyDecision::Deny => Decision {
            forward: false,
            audit_kind: AuditSinkKind::McpToolDenied,
            decision_str: "deny",
            method,
        },
        McpPolicyDecision::Prompt => match &ctx.gateway {
            None => {
                warn!(
                    bridge_id = %ctx.bridge_id,
                    "policy returned Prompt but no ApprovalGateway is wired; downgrading to audit_only"
                );
                Decision {
                    forward: true,
                    audit_kind: AuditSinkKind::McpToolCalled,
                    decision_str: "audit_only",
                    method,
                }
            }
            Some(gw) => {
                let request_id = new_request_id();
                let arguments = match parsed {
                    Some(McpMessage::ToolsCall { arguments, .. }) => arguments.clone(),
                    _ => serde_json::Value::Null,
                };
                let req = ApprovalRequest {
                    request_id,
                    category: ApprovalCategory::McpTool,
                    profile_name: APPROVAL_PROFILE_NAME.to_string(),
                    timeout_secs: APPROVAL_TIMEOUT_SECS,
                    created_at: Utc::now(),
                    payload: serde_json::json!({
                        "method": method,
                        "tool_name": tool,
                        "arguments": arguments,
                    }),
                    container_hint: Some(ctx.container_id.clone()),
                };
                let outcome = gw.request(req).await;
                if outcome.is_granted() {
                    Decision {
                        forward: true,
                        audit_kind: AuditSinkKind::McpToolCalled,
                        decision_str: "prompt_granted",
                        method,
                    }
                } else {
                    let decision_str = match outcome {
                        ApprovalOutcome::Denied { .. } => "prompt_denied",
                        ApprovalOutcome::TimedOut => "prompt_timed_out",
                        ApprovalOutcome::NoListener => "prompt_no_listener",
                        ApprovalOutcome::Granted { .. } => unreachable!(),
                    };
                    Decision {
                        forward: false,
                        audit_kind: AuditSinkKind::McpToolDenied,
                        decision_str,
                        method,
                    }
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::approval::{DenyAllApprovalGateway, NoopApprovalGateway};
    use linpodx_common::audit_sink::NoopAuditSink;
    use std::sync::Mutex as StdMutex;
    use tokio::io::duplex;

    #[test]
    fn extract_method_finds_field() {
        let m = extract_method(r#"{"jsonrpc":"2.0","method":"list_dirs","id":1}"#);
        assert_eq!(m.as_deref(), Some("list_dirs"));
    }

    #[test]
    fn extract_method_returns_none_for_non_json() {
        assert!(extract_method("not json at all").is_none());
    }

    #[test]
    fn extract_method_returns_none_when_field_absent() {
        assert!(extract_method(r#"{"id":1,"result":{}}"#).is_none());
    }

    #[test]
    fn extract_method_handles_non_string_method_field() {
        assert!(extract_method(r#"{"method": 42}"#).is_none());
    }

    #[test]
    fn allowlist_empty_is_audit_only() {
        let set: HashSet<String> = HashSet::new();
        assert_eq!(
            check_allowlist(&set, Some("anything")),
            AllowlistDecision::AuditOnly
        );
    }

    #[test]
    fn allowlist_hit_is_allowed() {
        let set: HashSet<String> = ["a".into(), "b".into()].into_iter().collect();
        assert_eq!(check_allowlist(&set, Some("a")), AllowlistDecision::Allowed);
    }

    #[test]
    fn allowlist_miss_is_denied() {
        let set: HashSet<String> = ["a".into()].into_iter().collect();
        assert_eq!(check_allowlist(&set, Some("b")), AllowlistDecision::Denied);
    }

    #[test]
    fn allowlist_methodless_is_audit_only() {
        let set: HashSet<String> = ["a".into()].into_iter().collect();
        assert_eq!(check_allowlist(&set, None), AllowlistDecision::AuditOnly);
    }

    /// Audit sink that records every entry into a shared Vec for assertion.
    struct CapturingSink {
        log: Arc<StdMutex<Vec<(AuditSinkKind, serde_json::Value)>>>,
    }

    impl AuditSink for CapturingSink {
        fn record(
            &self,
            kind: AuditSinkKind,
            _profile_name: Option<String>,
            _container_id: Option<String>,
            payload: serde_json::Value,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            let log = Arc::clone(&self.log);
            Box::pin(async move {
                log.lock().unwrap().push((kind, payload));
            })
        }
    }

    fn rule(method: &str, tool: Option<&str>, decision: McpPolicyDecision) -> McpPolicyRule {
        McpPolicyRule {
            method: method.to_string(),
            tool_name: tool.map(|s| s.to_string()),
            decision,
            note: None,
        }
    }

    fn empty_pump_ctx(
        sink: Arc<dyn AuditSink>,
        gateway: Option<Arc<dyn ApprovalGateway>>,
        rules: Vec<McpPolicyRule>,
    ) -> PumpContext {
        PumpContext {
            sink,
            allowlist: Arc::new(HashSet::new()),
            policy_store: Arc::new(RwLock::new(rules)),
            gateway,
            messages: Arc::new(AtomicU64::new(0)),
            container_id: "ctest".into(),
            bridge_id: "btest".into(),
            capabilities: Arc::new(RwLock::new(None)),
            subscriptions: Arc::new(RwLock::new(HashSet::new())),
            pending_initialize_ids: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    async fn run_pump_with(
        rules: Vec<McpPolicyRule>,
        gateway: Option<Arc<dyn ApprovalGateway>>,
        line: &str,
    ) -> (Vec<u8>, Vec<(AuditSinkKind, serde_json::Value)>) {
        let log: Arc<StdMutex<Vec<(AuditSinkKind, serde_json::Value)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let sink: Arc<dyn AuditSink> = Arc::new(CapturingSink {
            log: Arc::clone(&log),
        });

        let (mut input_w, input_r) = duplex(64);
        let (output_w, mut output_r) = duplex(64);

        let ctx = empty_pump_ctx(sink, gateway, rules);

        let pump_handle =
            tokio::spawn(async move { pump(BufReader::new(input_r), output_w, "test", ctx).await });

        let mut payload = line.to_string();
        if !payload.ends_with('\n') {
            payload.push('\n');
        }
        input_w.write_all(payload.as_bytes()).await.unwrap();
        drop(input_w);

        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut output_r, &mut out)
            .await
            .unwrap();
        pump_handle.await.unwrap();

        let entries = log.lock().unwrap().clone();
        (out, entries)
    }

    /// Run one pump direction with a shared `PumpContext` so tests can sequence
    /// host→container then container→host operations against the same subscription /
    /// initialize state.
    async fn run_pump_direction(
        ctx: PumpContext,
        direction: &'static str,
        lines: &[&str],
    ) -> Vec<u8> {
        let (mut input_w, input_r) = duplex(1024);
        let (output_w, mut output_r) = duplex(1024);

        let pump_handle =
            tokio::spawn(
                async move { pump(BufReader::new(input_r), output_w, direction, ctx).await },
            );

        for line in lines {
            let mut payload = line.to_string();
            if !payload.ends_with('\n') {
                payload.push('\n');
            }
            input_w.write_all(payload.as_bytes()).await.unwrap();
        }
        drop(input_w);

        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut output_r, &mut out)
            .await
            .unwrap();
        pump_handle.await.unwrap();
        out
    }

    #[tokio::test]
    async fn policy_auto_allow_forwards_and_audits_called() {
        let rules = vec![rule("tools/list", None, McpPolicyDecision::AutoAllow)];
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let (out, log) = run_pump_with(rules, None, line).await;
        assert!(!out.is_empty(), "AutoAllow should forward the message");
        assert!(log
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpToolCalled)));
    }

    #[tokio::test]
    async fn policy_deny_drops_and_audits_denied() {
        let rules = vec![rule("tools/call", None, McpPolicyDecision::Deny)];
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}"#;
        let (out, log) = run_pump_with(rules, None, line).await;
        assert!(out.is_empty(), "Deny must drop");
        assert!(log
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpToolDenied)));
    }

    #[tokio::test]
    async fn policy_prompt_grants_via_gateway() {
        let rules = vec![rule("tools/call", None, McpPolicyDecision::Prompt)];
        let gw: Arc<dyn ApprovalGateway> = Arc::new(NoopApprovalGateway);
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}"#;
        let (out, log) = run_pump_with(rules, Some(gw), line).await;
        assert!(!out.is_empty(), "Granted prompt must forward");
        let last = log.last().expect("audit entry");
        assert!(matches!(last.0, AuditSinkKind::McpToolCalled));
        assert_eq!(
            last.1.get("decision").and_then(|v| v.as_str()),
            Some("prompt_granted")
        );
    }

    #[tokio::test]
    async fn policy_prompt_denied_drops_when_gateway_says_no() {
        let rules = vec![rule("tools/call", None, McpPolicyDecision::Prompt)];
        let gw: Arc<dyn ApprovalGateway> = Arc::new(DenyAllApprovalGateway);
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}"#;
        let (out, log) = run_pump_with(rules, Some(gw), line).await;
        assert!(out.is_empty(), "Denied prompt must drop");
        let last = log.last().expect("audit entry");
        assert!(matches!(last.0, AuditSinkKind::McpToolDenied));
        assert_eq!(
            last.1.get("decision").and_then(|v| v.as_str()),
            Some("prompt_denied")
        );
    }

    #[tokio::test]
    async fn policy_prompt_without_gateway_downgrades_to_audit_only() {
        let rules = vec![rule("tools/call", None, McpPolicyDecision::Prompt)];
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}"#;
        let (out, log) = run_pump_with(rules, None, line).await;
        assert!(!out.is_empty(), "no gateway → audit-only forwards");
        assert!(log
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpToolCalled)));
    }

    #[tokio::test]
    async fn empty_policy_store_falls_back_to_legacy_allowlist_path() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        // No rules, no gateway, no allowlist. Should be audit-only forward.
        let (out, log) = run_pump_with(vec![], None, line).await;
        assert!(!out.is_empty());
        assert!(log
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpToolCalled)));
    }

    #[tokio::test]
    async fn unparseable_frame_denied_under_active_policy() {
        // A configured policy (non-empty store) must fail *closed* on a frame this crate's
        // parser rejects — otherwise a parser-differential payload bypasses every Deny rule.
        let rules = vec![rule("tools/call", None, McpPolicyDecision::Deny)];
        let line = "this is not valid json at all";
        let (out, log) = run_pump_with(rules, None, line).await;
        assert!(
            out.is_empty(),
            "unparseable frame must be dropped under an active policy"
        );
        let last = log.last().expect("audit entry");
        assert!(
            matches!(last.0, AuditSinkKind::McpToolDenied),
            "denied unparseable frame audits as McpToolDenied"
        );
        assert_eq!(
            last.1.get("decision").and_then(|v| v.as_str()),
            Some("unparseable_denied"),
            "distinct decision marker for unparseable frames"
        );
    }

    #[tokio::test]
    async fn parseable_unmatched_method_denied_under_denylist_policy() {
        // With any Deny rule present, an unmatched (but parseable) method inherits the
        // derived default action of Deny rather than fail-open forwarding.
        let rules = vec![rule(
            "tools/call",
            Some("write_file"),
            McpPolicyDecision::Deny,
        )];
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let (out, log) = run_pump_with(rules, None, line).await;
        assert!(out.is_empty(), "unmatched method under denylist must drop");
        assert!(log
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpToolDenied)));
    }

    #[tokio::test]
    async fn unparseable_frame_forwarded_in_pure_legacy_mode() {
        // No policy configured → the legacy static-allowlist path runs. An empty allowlist
        // treats method-less/malformed lines as audit-only and forwards them, preserving
        // pre-2E behavior.
        let line = "not valid json";
        let (out, log) = run_pump_with(vec![], None, line).await;
        assert!(
            !out.is_empty(),
            "pure-legacy mode forwards unparseable frames audit-only"
        );
        assert!(log
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpToolCalled)));
    }

    #[tokio::test]
    async fn registry_constructs_with_or_without_policy() {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let _r1 = BridgeRegistry::new(Arc::clone(&sink));
        let store = empty_policy_store();
        let _r2 =
            BridgeRegistry::with_policy_and_gateway(Arc::clone(&sink), Arc::clone(&store), None);
    }

    // ----- Phase 2F: notifications + capabilities -----

    type AuditLog = Arc<StdMutex<Vec<(AuditSinkKind, serde_json::Value)>>>;

    fn fresh_log() -> (AuditLog, Arc<dyn AuditSink>) {
        let log: AuditLog = Arc::new(StdMutex::new(Vec::new()));
        let sink: Arc<dyn AuditSink> = Arc::new(CapturingSink {
            log: Arc::clone(&log),
        });
        (log, sink)
    }

    #[tokio::test]
    async fn subscribe_then_updated_forwards_only_subscribed_uri() {
        let (log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        // Host subscribes file:///x.
        let sub_line = r#"{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"file:///x"}}"#;
        let host_out =
            run_pump_direction(ctx.clone(), DIRECTION_HOST_TO_CONTAINER, &[sub_line]).await;
        assert!(!host_out.is_empty(), "subscribe must forward to container");

        // Container pushes update for the subscribed URI → forwarded.
        let upd_subscribed = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///x"}}"#;
        let out1 =
            run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[upd_subscribed]).await;
        assert!(!out1.is_empty(), "subscribed URI update must forward");

        // Container pushes update for a different URI → dropped.
        let upd_other = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///y"}}"#;
        let out2 = run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[upd_other]).await;
        assert!(out2.is_empty(), "unsubscribed URI update must be dropped");

        // Audit log should show: McpResourceSubscribed, McpResourceUpdated x2 (one
        // forwarded_subscribed, one dropped_unsubscribed).
        let entries = log.lock().unwrap().clone();
        assert!(entries
            .iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpResourceSubscribed)));
        let updated: Vec<_> = entries
            .iter()
            .filter(|(k, _)| matches!(k, AuditSinkKind::McpResourceUpdated))
            .collect();
        assert_eq!(
            updated.len(),
            2,
            "two resources/updated audit entries expected"
        );
        let decisions: Vec<&str> = updated
            .iter()
            .map(|(_, v)| v.get("decision").and_then(|d| d.as_str()).unwrap_or(""))
            .collect();
        assert!(decisions.contains(&"forwarded_subscribed"));
        assert!(decisions.contains(&"dropped_unsubscribed"));
    }

    #[tokio::test]
    async fn unsubscribe_removes_uri_and_stops_forwarding_updates() {
        let (_log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        let sub = r#"{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"file:///x"}}"#;
        let unsub = r#"{"jsonrpc":"2.0","id":2,"method":"resources/unsubscribe","params":{"uri":"file:///x"}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_HOST_TO_CONTAINER, &[sub, unsub]).await;

        // Subscriptions set should now be empty.
        let subs: Vec<String> = ctx.subscriptions.read().await.iter().cloned().collect();
        assert!(subs.is_empty(), "unsubscribe must clear the URI");

        let upd = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///x"}}"#;
        let out = run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[upd]).await;
        assert!(out.is_empty(), "after unsubscribe, updates are dropped");
    }

    #[tokio::test]
    async fn list_changed_notifications_always_forward_with_audit() {
        let (log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        let lines = [
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#,
        ];
        let out = run_pump_direction(ctx, DIRECTION_CONTAINER_TO_HOST, &lines).await;
        assert!(!out.is_empty(), "list_changed must forward");

        let entries = log.lock().unwrap().clone();
        let count = entries
            .iter()
            .filter(|(k, _)| matches!(k, AuditSinkKind::McpListChanged))
            .count();
        assert_eq!(count, 3, "all three list_changed flavors audited");
    }

    #[tokio::test]
    async fn initialize_request_then_response_populates_capabilities() {
        let (log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        // Host sends initialize request with id=42.
        let init =
            r#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":{"protocolVersion":"1.0"}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_HOST_TO_CONTAINER, &[init]).await;

        let pending: Vec<i64> = ctx
            .pending_initialize_ids
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        assert_eq!(pending, vec![42], "host-side must record the initialize id");

        // Container responds with capabilities matching id=42.
        let resp = r#"{"jsonrpc":"2.0","id":42,"result":{"capabilities":{"tools":{},"resources":{"subscribe":true},"experimental":{"foo":"bar"}}}}"#;
        let out = run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[resp]).await;
        assert!(!out.is_empty(), "initialize response is forwarded");

        let caps = ctx.capabilities.read().await.clone().expect("populated");
        assert!(caps.tools);
        assert!(caps.resources);
        assert!(!caps.prompts);
        assert!(!caps.logging);
        assert_eq!(
            caps.experimental.get("foo").and_then(|v| v.as_str()),
            Some("bar")
        );

        // Audit log includes the initialize_complete marker.
        let entries = log.lock().unwrap().clone();
        let init_complete = entries.iter().any(|(k, v)| {
            matches!(k, AuditSinkKind::McpListChanged)
                && v.get("decision").and_then(|d| d.as_str()) == Some("initialize_complete")
        });
        assert!(init_complete, "initialize_complete audit entry expected");

        // pending_initialize_ids consumed.
        assert!(ctx.pending_initialize_ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn initialize_response_with_mismatched_id_is_ignored() {
        let (_log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_HOST_TO_CONTAINER, &[init]).await;

        // Different id — must not populate capabilities.
        let resp = r#"{"jsonrpc":"2.0","id":99,"result":{"capabilities":{"tools":{}}}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[resp]).await;

        assert!(ctx.capabilities.read().await.is_none());
        // pending id remains because no match consumed it.
        let still_pending: Vec<i64> = ctx
            .pending_initialize_ids
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        assert_eq!(still_pending, vec![1]);
    }

    #[tokio::test]
    async fn concurrent_initialize_responses_arrive_out_of_order() {
        // Two Initialize requests in-flight (ids 7 and 9). The container responds for 9
        // first, then 7. Both responses must populate capabilities and remove their id
        // from the pending set. Last-write wins on the capability cache, but order
        // doesn't matter for set membership.
        let (_log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        let init_7 = r#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}"#;
        let init_9 = r#"{"jsonrpc":"2.0","id":9,"method":"initialize","params":{}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_HOST_TO_CONTAINER, &[init_7, init_9]).await;

        let pending: HashSet<i64> = ctx
            .pending_initialize_ids
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        assert!(
            pending.contains(&7) && pending.contains(&9),
            "both ids tracked"
        );

        // Response for id=9 arrives first.
        let resp_9 = r#"{"jsonrpc":"2.0","id":9,"result":{"capabilities":{"tools":{}}}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[resp_9]).await;
        assert!(
            ctx.capabilities.read().await.is_some(),
            "id=9 populates caps"
        );
        let after_9: HashSet<i64> = ctx
            .pending_initialize_ids
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        assert_eq!(after_9, [7].into_iter().collect());

        // Response for id=7 arrives next — also populates caps (last-write wins) and
        // removes id 7 from the pending set.
        let resp_7 = r#"{"jsonrpc":"2.0","id":7,"result":{"capabilities":{"prompts":{}}}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_CONTAINER_TO_HOST, &[resp_7]).await;
        let caps = ctx.capabilities.read().await.clone().expect("populated");
        assert!(caps.prompts, "id=7 last-write applied prompts capability");
        assert!(
            ctx.pending_initialize_ids.lock().await.is_empty(),
            "both ids consumed"
        );
    }

    #[tokio::test]
    async fn duplicate_initialize_id_is_idempotent() {
        // Sending the same Initialize id twice should leave the set with a single
        // entry — `HashSet::insert` is the natural fit and protects against host-side
        // retransmits.
        let (_log, sink) = fresh_log();
        let ctx = empty_pump_ctx(sink, None, vec![]);

        let init = r#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":{}}"#;
        run_pump_direction(ctx.clone(), DIRECTION_HOST_TO_CONTAINER, &[init, init]).await;

        let pending: HashSet<i64> = ctx
            .pending_initialize_ids
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        assert_eq!(pending, [42].into_iter().collect());
    }

    #[tokio::test]
    async fn registry_capabilities_unknown_bridge_returns_none() {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let reg = BridgeRegistry::new(sink);
        assert!(reg.capabilities("does-not-exist").await.is_none());
        assert!(reg.subscriptions("does-not-exist").await.is_none());
    }
}
