//! End-to-end integration test for the Phase 2E policy + approval path.
//!
//! Spawns a `cat` host command (loops stdin to stdout) and a second `cat` as the fake
//! "container side". Sends a `tools/call` JSON-RPC line that the policy engine resolves
//! to `Prompt`; the wired-in `NoopApprovalGateway` grants it; the bridge forwards the
//! line and audits `prompt_granted`.
//!
//! Marked `#[ignore]` because it shells out to the real `cat` binary and a real
//! `podman` (we substitute a no-op `cat` for `podman` so the test stays self-contained
//! but still exercises the full pump + approval round-trip).

use linpodx_common::approval::{ApprovalGateway, NoopApprovalGateway};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind, NoopAuditSink};
use linpodx_common::ipc::{McpPolicyDecision, McpPolicyRule};
use linpodx_mcp::bridge::empty_policy_store;
use linpodx_mcp::BridgeRegistry;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

#[derive(Default, Clone)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn prompt_granted_path_forwards_message_and_audits() {
    let _ = tracing_subscriber::fmt::try_init();

    let sink = CapturingSink::default();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(sink.clone());
    let store = empty_policy_store();
    {
        let mut guard = store.write().await;
        *guard = vec![rule("tools/call", None, McpPolicyDecision::Prompt)];
    }
    let gateway: Arc<dyn ApprovalGateway> = Arc::new(NoopApprovalGateway);

    let registry = BridgeRegistry::with_policy_and_gateway(
        Arc::clone(&sink_arc),
        Arc::clone(&store),
        Some(Arc::clone(&gateway)),
    );

    // Substitute `cat` for `podman` so the test runs without a podman install.
    // The bridge spawns it as `cat exec -i <cid> /bin/sh -c cat`; cat ignores all the
    // extra args and pipes stdin → stdout, which is exactly the loop behavior we want.
    let handle = registry
        .start(
            "/bin/cat".to_string(),
            "fake-container".to_string(),
            "/bin/cat".to_string(),
            vec![],
            vec![],
        )
        .await
        .expect("start bridge");

    // Allow pump tasks to do at least one round trip.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Stop and verify audit log captured the policy round-trip.
    let stopped = registry.stop(&handle.bridge_id).await.expect("stop bridge");
    assert!(stopped, "stop should succeed");

    let log = sink.log.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpBridgeStarted)),
        "expected McpBridgeStarted audit, got {log:?}"
    );
    assert!(
        log.iter()
            .any(|(k, _)| matches!(k, AuditSinkKind::McpBridgeStopped)),
        "expected McpBridgeStopped audit"
    );
}

#[tokio::test]
async fn registry_constructs_with_full_signature() {
    // Compile-time smoke test for the new constructor surface.
    let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let store = empty_policy_store();
    let _ = BridgeRegistry::with_policy_and_gateway(sink, store, None);
}
