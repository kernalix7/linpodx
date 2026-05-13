use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// Categories of policy violations that a profile can mark as "ask the human first".
/// Phase 2A enforces the two categories that the policy engine already detects at create
/// time. Runtime-emitted categories (`NetworkEgress`, `FsWriteOutsideWorkspace`,
/// `PrivilegedOp`) land in Phase 2C+ when MCP / instrumented runtime ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalCategory {
    /// `linpodx run -v /host/path:/dst …` where the source isn't in the profile's mount
    /// whitelist.
    MountHostPath,
    /// Caller asked to add a Linux capability the profile doesn't already grant.
    CapAdd,
    /// MCP bridge observed an inbound tool call with a method name not in the allowlist
    /// (Phase 2D). Payload includes the JSON method + best-effort param summary.
    McpTool,
}

impl ApprovalCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MountHostPath => "mount_host_path",
            Self::CapAdd => "cap_add",
            Self::McpTool => "mcp_tool",
        }
    }
}

impl std::fmt::Display for ApprovalCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One side of the approval handshake — what the daemon asks the listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub category: ApprovalCategory,
    pub profile_name: String,
    pub timeout_secs: u64,
    pub created_at: DateTime<Utc>,
    /// Per-category structured payload (e.g. mount source/destination) — opaque to the trait.
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Best-effort hint about which container would be created if approved (often unset
    /// because the container ID isn't allocated until podman create runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_hint: Option<String>,
}

/// What the approval handshake resolves to. `Granted` and `Denied` carry caller info from
/// the listener; `TimedOut` and `NoListener` are server-internal verdicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Granted {
        #[serde(default)]
        by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Denied {
        #[serde(default)]
        by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    TimedOut,
    NoListener,
}

impl ApprovalOutcome {
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

/// Notification fanned out after an approval request resolves. Lets listeners that
/// rendered the prompt dismiss it without polling. Phase 2A follow-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolved {
    pub request_id: String,
    pub outcome: ApprovalOutcome,
}

/// Object-safe abstraction so subsystems (sandbox, future MCP bridge) don't depend on the
/// daemon-internal `ApprovalRegistry`. The daemon's registry implements this on top of a
/// broadcast channel + pending-request map.
pub trait ApprovalGateway: Send + Sync {
    fn request(
        &self,
        req: ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalOutcome> + Send + '_>>;
}

/// Test / fallback gateway. Always returns `Granted { by: "noop" }` immediately. Useful
/// when wiring policy code in environments without a daemon (unit tests, dry-run tools).
#[derive(Debug, Default)]
pub struct NoopApprovalGateway;

impl ApprovalGateway for NoopApprovalGateway {
    fn request(
        &self,
        _req: ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalOutcome> + Send + '_>> {
        Box::pin(async {
            ApprovalOutcome::Granted {
                by: "noop".to_string(),
                reason: None,
            }
        })
    }
}

/// Always-deny variant for tests that want to verify the deny path.
#[derive(Debug, Default)]
pub struct DenyAllApprovalGateway;

impl ApprovalGateway for DenyAllApprovalGateway {
    fn request(
        &self,
        _req: ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = ApprovalOutcome> + Send + '_>> {
        Box::pin(async {
            ApprovalOutcome::Denied {
                by: "deny-all-test".to_string(),
                reason: Some("DenyAllApprovalGateway in use".into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_serializes_snake_case() {
        let s = serde_json::to_string(&ApprovalCategory::MountHostPath).unwrap();
        assert_eq!(s, "\"mount_host_path\"");
        let s = serde_json::to_string(&ApprovalCategory::CapAdd).unwrap();
        assert_eq!(s, "\"cap_add\"");
        let parsed: ApprovalCategory = serde_json::from_str("\"mount_host_path\"").unwrap();
        assert_eq!(parsed, ApprovalCategory::MountHostPath);
    }

    #[test]
    fn request_round_trips() {
        let req = ApprovalRequest {
            request_id: "req-1".into(),
            category: ApprovalCategory::CapAdd,
            profile_name: "demo".into(),
            timeout_secs: 30,
            created_at: Utc::now(),
            payload: serde_json::json!({"cap": "SETUID"}),
            container_hint: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: ApprovalRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.request_id, "req-1");
        assert_eq!(back.category, ApprovalCategory::CapAdd);
    }

    #[test]
    fn outcome_round_trips() {
        let g = ApprovalOutcome::Granted {
            by: "alice".into(),
            reason: Some("ok".into()),
        };
        let s = serde_json::to_string(&g).unwrap();
        assert!(s.contains("\"outcome\":\"granted\""));
        let back: ApprovalOutcome = serde_json::from_str(&s).unwrap();
        assert!(back.is_granted());

        let to = ApprovalOutcome::TimedOut;
        let s = serde_json::to_string(&to).unwrap();
        assert!(s.contains("\"timed_out\""));
    }

    #[tokio::test]
    async fn noop_gateway_grants() {
        let gw: Box<dyn ApprovalGateway> = Box::new(NoopApprovalGateway);
        let outcome = gw
            .request(ApprovalRequest {
                request_id: "x".into(),
                category: ApprovalCategory::MountHostPath,
                profile_name: "test".into(),
                timeout_secs: 5,
                created_at: Utc::now(),
                payload: serde_json::Value::Null,
                container_hint: None,
            })
            .await;
        assert!(outcome.is_granted());
    }

    #[tokio::test]
    async fn deny_all_gateway_denies() {
        let gw: Box<dyn ApprovalGateway> = Box::new(DenyAllApprovalGateway);
        let outcome = gw
            .request(ApprovalRequest {
                request_id: "x".into(),
                category: ApprovalCategory::CapAdd,
                profile_name: "test".into(),
                timeout_secs: 5,
                created_at: Utc::now(),
                payload: serde_json::Value::Null,
                container_hint: None,
            })
            .await;
        assert!(matches!(outcome, ApprovalOutcome::Denied { .. }));
    }
}
