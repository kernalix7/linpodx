use linpodx_common::approval::{
    ApprovalGateway, ApprovalOutcome, ApprovalRequest, ApprovalResolved,
};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_plugin::{PluginDecision, PluginRegistry};
use linpodx_sandbox::PluginStore;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tracing::{debug, info, warn};

const APPROVAL_CHANNEL_CAPACITY: usize = 1024;

/// Daemon-side approval orchestrator. Implements `ApprovalGateway` for the sandbox
/// subsystem and exposes a broadcast channel that `server.rs` subscribes connections
/// to for fanning approval requests out to CLI / GUI listeners.
pub struct ApprovalRegistry {
    requests: broadcast::Sender<ApprovalRequest>,
    /// Fan-out for resolved-request notifications so other listeners that rendered the
    /// prompt can dismiss it without polling.
    resolved: broadcast::Sender<ApprovalResolved>,
    pending: Mutex<HashMap<String, oneshot::Sender<ApprovalOutcome>>>,
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(APPROVAL_CHANNEL_CAPACITY);
        let (rtx, _rrx) = broadcast::channel(APPROVAL_CHANNEL_CAPACITY);
        Self {
            requests: tx,
            resolved: rtx,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe a connection to the approval-request fan-out.
    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.requests.subscribe()
    }

    /// Subscribe a connection to the approval-resolved fan-out (Phase 2A follow-up).
    pub fn subscribe_resolved(&self) -> broadcast::Receiver<ApprovalResolved> {
        self.resolved.subscribe()
    }

    /// Resolve an outstanding request. Returns `true` if the daemon was still waiting
    /// (the listener won the race), `false` otherwise (already resolved or unknown).
    pub fn respond(&self, request_id: &str, outcome: ApprovalOutcome) -> bool {
        let sender = {
            let mut guard = self.pending.lock().expect("approval registry poisoned");
            guard.remove(request_id)
        };
        match sender {
            Some(tx) => {
                let _ = tx.send(outcome.clone());
                // Best-effort fan-out — failure (no listeners) is not an error.
                let _ = self.resolved.send(ApprovalResolved {
                    request_id: request_id.to_string(),
                    outcome,
                });
                true
            }
            None => {
                debug!(
                    request_id,
                    "approval response for unknown / already-resolved request"
                );
                false
            }
        }
    }

    /// Internal helper used by the trait impl. Registers a oneshot, fans out the request
    /// to listeners via broadcast, then waits with a timeout.
    async fn request_inner(&self, req: ApprovalRequest, timeout: Duration) -> ApprovalOutcome {
        let request_id = req.request_id.clone();
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().expect("approval registry poisoned");
            guard.insert(request_id.clone(), tx);
        }

        let listeners = self.requests.send(req).unwrap_or_default();
        if listeners == 0 {
            // Drop the pending entry — no one will ever respond.
            let _ = self
                .pending
                .lock()
                .expect("approval registry poisoned")
                .remove(&request_id);
            warn!(request_id, "approval request fired with no listeners");
            return ApprovalOutcome::NoListener;
        }
        info!(request_id, listeners, "approval request fanned out");

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => {
                // Sender dropped without sending — treat as TimedOut.
                ApprovalOutcome::TimedOut
            }
            Err(_) => {
                // Timeout — make sure the entry is cleaned up so we don't leak memory.
                let _ = self
                    .pending
                    .lock()
                    .expect("approval registry poisoned")
                    .remove(&request_id);
                ApprovalOutcome::TimedOut
            }
        }
    }
}

impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalGateway for ApprovalRegistry {
    fn request(
        &self,
        req: ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalOutcome> + Send + '_>> {
        let timeout = Duration::from_secs(req.timeout_secs.max(1));
        Box::pin(self.request_inner(req, timeout))
    }
}

/// Wraps an inner [`ApprovalGateway`] (typically [`ApprovalRegistry`]) and consults the
/// enabled WASM plugins first. A plugin returning [`PluginDecision::Allow`] short-circuits
/// the human listener; [`PluginDecision::Deny`] rejects without prompting; otherwise the
/// request falls through to the inner gateway.
///
/// Plugin combination follows `Deny > Allow > Defer` — a single deny vetoes any concurrent
/// allows. The plugin pool is rebuilt per call from the SQLite-backed store so a freshly
/// installed/disabled plugin takes effect without a daemon restart.
pub struct PluginAwareApprovalGateway {
    inner: Arc<dyn ApprovalGateway>,
    plugins: Arc<PluginStore>,
    audit: Arc<dyn AuditSink>,
}

impl PluginAwareApprovalGateway {
    pub fn new(
        inner: Arc<dyn ApprovalGateway>,
        plugins: Arc<PluginStore>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            inner,
            plugins,
            audit,
        }
    }

    async fn evaluate_plugins(
        &self,
        req: &ApprovalRequest,
    ) -> Option<(PluginDecision, String, String)> {
        let specs = match self.plugins.list_enabled_specs().await {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => return None,
            Err(e) => {
                warn!(error = %e, "plugin store query failed; skipping plugin evaluation");
                return None;
            }
        };
        let payload = serde_json::to_vec(req).unwrap_or_default();
        // wasmtime instances are not Send across awaits; build + run on a blocking task.
        let result = tokio::task::spawn_blocking(move || {
            let mut reg = match PluginRegistry::new() {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "plugin registry init failed");
                    return Vec::new();
                }
            };
            reg.load_all(&specs);
            reg.evaluate_approval(&payload)
        })
        .await;
        let decisions = match result {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "plugin evaluation task join failed");
                return None;
            }
        };
        if decisions.is_empty() {
            return None;
        }
        // Combine: Deny > Allow > Defer.
        let mut combined = (PluginDecision::Defer, String::new(), String::new());
        for (name, decision, reason) in decisions {
            match decision {
                PluginDecision::Deny => {
                    combined = (PluginDecision::Deny, name, reason);
                    break;
                }
                PluginDecision::Allow if combined.0 != PluginDecision::Allow => {
                    combined = (PluginDecision::Allow, name, reason);
                }
                _ => {}
            }
        }
        if combined.0 == PluginDecision::Defer {
            None
        } else {
            Some(combined)
        }
    }
}

impl ApprovalGateway for PluginAwareApprovalGateway {
    fn request(
        &self,
        req: ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalOutcome> + Send + '_>> {
        Box::pin(async move {
            if let Some((decision, plugin_name, reason)) = self.evaluate_plugins(&req).await {
                let payload = serde_json::json!({
                    "request_id": req.request_id,
                    "category": req.category.as_str(),
                    "profile_name": req.profile_name,
                    "plugin": plugin_name,
                    "decision": match decision {
                        PluginDecision::Allow => "allow",
                        PluginDecision::Deny => "deny",
                        PluginDecision::Defer => "defer",
                    },
                    "reason": reason,
                });
                self.audit
                    .record(AuditSinkKind::PluginInvoked, None, None, payload)
                    .await;
                let by = format!("plugin:{plugin_name}");
                let reason_opt = if reason.is_empty() {
                    None
                } else {
                    Some(reason)
                };
                return match decision {
                    PluginDecision::Allow => ApprovalOutcome::Granted {
                        by,
                        reason: reason_opt,
                    },
                    PluginDecision::Deny => ApprovalOutcome::Denied {
                        by,
                        reason: reason_opt,
                    },
                    PluginDecision::Defer => self.inner.request(req).await,
                };
            }
            self.inner.request(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::approval::ApprovalCategory;

    fn req(id: &str, secs: u64) -> ApprovalRequest {
        ApprovalRequest {
            request_id: id.into(),
            category: ApprovalCategory::MountHostPath,
            profile_name: "test".into(),
            timeout_secs: secs,
            created_at: chrono::Utc::now(),
            payload: serde_json::Value::Null,
            container_hint: None,
        }
    }

    #[tokio::test]
    async fn no_listener_returns_no_listener_outcome() {
        let reg = ApprovalRegistry::new();
        let outcome = reg.request_inner(req("a", 5), Duration::from_secs(5)).await;
        assert!(matches!(outcome, ApprovalOutcome::NoListener));
    }

    #[tokio::test]
    async fn listener_grants_via_respond() {
        let reg = std::sync::Arc::new(ApprovalRegistry::new());
        let mut rx = reg.subscribe();
        let reg2 = reg.clone();
        let task = tokio::spawn(async move {
            let received = rx.recv().await.unwrap();
            reg2.respond(
                &received.request_id,
                ApprovalOutcome::Granted {
                    by: "test".into(),
                    reason: None,
                },
            )
        });
        let outcome = reg.request_inner(req("b", 5), Duration::from_secs(5)).await;
        assert!(matches!(outcome, ApprovalOutcome::Granted { .. }));
        let accepted = task.await.unwrap();
        assert!(accepted);
    }

    #[tokio::test]
    async fn double_respond_is_ignored() {
        let reg = std::sync::Arc::new(ApprovalRegistry::new());
        let mut rx = reg.subscribe();
        let reg2 = reg.clone();
        tokio::spawn(async move {
            let r = rx.recv().await.unwrap();
            reg2.respond(
                &r.request_id,
                ApprovalOutcome::Granted {
                    by: "a".into(),
                    reason: None,
                },
            );
        });
        let outcome = reg.request_inner(req("c", 5), Duration::from_secs(5)).await;
        assert!(matches!(outcome, ApprovalOutcome::Granted { .. }));
        // Second response should be rejected.
        let again = reg.respond(
            "c",
            ApprovalOutcome::Denied {
                by: "b".into(),
                reason: None,
            },
        );
        assert!(!again);
    }

    #[tokio::test]
    async fn timeout_returns_timed_out_and_clears_entry() {
        let reg = std::sync::Arc::new(ApprovalRegistry::new());
        let _rx = reg.subscribe(); // active listener but never responds
        let outcome = reg
            .request_inner(req("d", 1), Duration::from_millis(50))
            .await;
        assert!(matches!(outcome, ApprovalOutcome::TimedOut));
        // Pending map should be cleared so a late respond returns false.
        let late = reg.respond(
            "d",
            ApprovalOutcome::Granted {
                by: "x".into(),
                reason: None,
            },
        );
        assert!(!late);
    }

    #[tokio::test]
    async fn respond_fans_out_resolved_notification() {
        let reg = std::sync::Arc::new(ApprovalRegistry::new());
        let mut rx_req = reg.subscribe();
        let mut rx_res = reg.subscribe_resolved();
        let reg2 = reg.clone();
        tokio::spawn(async move {
            let r = rx_req.recv().await.unwrap();
            reg2.respond(
                &r.request_id,
                ApprovalOutcome::Granted {
                    by: "test".into(),
                    reason: None,
                },
            );
        });
        let outcome = reg.request_inner(req("e", 5), Duration::from_secs(5)).await;
        assert!(outcome.is_granted());
        let resolved = tokio::time::timeout(Duration::from_secs(1), rx_res.recv())
            .await
            .expect("recv resolved within timeout")
            .expect("resolved sender alive");
        assert_eq!(resolved.request_id, "e");
        assert!(resolved.outcome.is_granted());
    }

    #[tokio::test]
    async fn unknown_request_id_response_returns_false() {
        let reg = ApprovalRegistry::new();
        let result = reg.respond(
            "unknown",
            ApprovalOutcome::Granted {
                by: "x".into(),
                reason: None,
            },
        );
        assert!(!result);
    }
}
