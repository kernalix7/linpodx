//! MCP bridge + per-method approval policy dispatch handlers.

use super::*;

impl Dispatcher {
    pub(crate) async fn mcp_bridge_start(
        &self,
        p: linpodx_common::ipc::McpBridgeStartParams,
    ) -> Result<serde_json::Value> {
        let handle = self
            .bridges
            .start(
                self.podman_bin.clone(),
                p.container_id,
                p.host_command,
                p.host_args,
                p.allowlist,
            )
            .await
            .map_err(|e| Error::Runtime {
                message: format!("mcp bridge start failed: {e}"),
            })?;
        Ok(serde_json::to_value(responses::McpBridgeStartResponse {
            bridge_id: handle.bridge_id,
        })?)
    }

    pub(crate) async fn mcp_bridge_stop(
        &self,
        p: linpodx_common::ipc::McpBridgeStopParams,
    ) -> Result<serde_json::Value> {
        let stopped = self
            .bridges
            .stop(&p.bridge_id)
            .await
            .map_err(|e| Error::Runtime {
                message: format!("mcp bridge stop failed: {e}"),
            })?;
        Ok(serde_json::to_value(responses::McpBridgeStopResponse {
            bridge_id: p.bridge_id,
            stopped,
        })?)
    }

    pub(crate) async fn mcp_bridge_status(
        &self,
        p: linpodx_common::ipc::McpBridgeStatusParams,
    ) -> Result<serde_json::Value> {
        let entries = self.bridges.status(p.bridge_id.as_deref()).await;
        let view: Vec<responses::McpBridgeStatusEntry> = entries
            .into_iter()
            .map(|e| responses::McpBridgeStatusEntry {
                bridge_id: e.bridge_id,
                container_id: e.container_id,
                host_command: e.host_command,
                started_at: e.started_at,
                messages_seen: e.messages_seen,
            })
            .collect();
        Ok(serde_json::to_value(view)?)
    }

    pub(crate) async fn mcp_policy_list(&self) -> Result<serde_json::Value> {
        let store = linpodx_sandbox::McpPolicyStore::new(self.session.db());
        let rules = store.list().await?;
        Ok(serde_json::to_value(rules)?)
    }

    pub(crate) async fn mcp_policy_set(
        &self,
        p: linpodx_common::ipc::McpPolicySetParams,
    ) -> Result<serde_json::Value> {
        let db = self.session.db();
        let sink = linpodx_sandbox::SandboxAuditSink::new(Arc::clone(&db));
        let (upserted, deleted) =
            linpodx_sandbox::apply_mcp_policy_set(&db, &sink, p.rules, p.replace_all).await?;
        // Refresh the in-memory policy store so running bridges pick up new rules
        // immediately (no need to restart bridges).
        let new_rules = linpodx_sandbox::McpPolicyStore::new(Arc::clone(&db))
            .load_all()
            .await?;
        let store = self.bridges.policy_store();
        let mut guard = store.write().await;
        *guard = new_rules;
        Ok(serde_json::to_value(responses::McpPolicySetResponse {
            upserted,
            deleted,
        })?)
    }

    pub(crate) async fn mcp_bridge_capabilities(
        &self,
        p: linpodx_common::ipc::McpBridgeCapabilitiesParams,
    ) -> Result<serde_json::Value> {
        let caps = self
            .bridges
            .capabilities(&p.bridge_id)
            .await
            .unwrap_or_default();
        Ok(serde_json::to_value(caps)?)
    }

    pub(crate) async fn mcp_bridge_subscriptions(
        &self,
        p: linpodx_common::ipc::McpBridgeSubscriptionsParams,
    ) -> Result<serde_json::Value> {
        let subs = self
            .bridges
            .subscriptions(&p.bridge_id)
            .await
            .unwrap_or_default();
        Ok(serde_json::to_value(subs)?)
    }
}
