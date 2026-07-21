//! WASM plugin SDK + plugin-key (list/revoke/Raft-propagate) dispatch handlers.

use super::*;

impl Dispatcher {
    pub(crate) async fn plugin_list(&self) -> Result<serde_json::Value> {
        let store = PluginStore::new(Arc::clone(self.snapshot.database()));
        let summary = store.list().await?;
        Ok(serde_json::to_value(summary)?)
    }

    pub(crate) async fn plugin_install(
        &self,
        p: linpodx_common::ipc::PluginInstallParams,
    ) -> Result<serde_json::Value> {
        let store = PluginStore::new(Arc::clone(self.snapshot.database()));
        let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
        let resp = store.install(&sink, &p).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn plugin_enable(
        &self,
        p: linpodx_common::ipc::PluginNameParams,
    ) -> Result<serde_json::Value> {
        let store = PluginStore::new(Arc::clone(self.snapshot.database()));
        let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
        let resp = store.enable(&sink, &p.name).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn plugin_disable(
        &self,
        p: linpodx_common::ipc::PluginNameParams,
    ) -> Result<serde_json::Value> {
        let store = PluginStore::new(Arc::clone(self.snapshot.database()));
        let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
        let resp = store.disable(&sink, &p.name).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn plugin_remove(
        &self,
        p: linpodx_common::ipc::PluginRemoveParams,
    ) -> Result<serde_json::Value> {
        let store = PluginStore::new(Arc::clone(self.snapshot.database()));
        let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
        let resp = store.remove(&sink, &p).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn plugin_key_list(&self) -> Result<serde_json::Value> {
        let registry = linpodx_plugin::KeyRegistry::from_env();
        let entries = registry
            .list_keys()
            .into_iter()
            .map(|e| responses::PluginKeyEntry {
                publisher: e.publisher,
                fingerprint: e.fingerprint,
                status: e.status,
                revoked_at: e.revoked_at,
                reason: e.reason,
            })
            .collect::<responses::PluginKeyListResponse>();
        Ok(serde_json::to_value(entries)?)
    }

    pub(crate) async fn plugin_key_revoke(
        &self,
        p: linpodx_common::ipc::PluginKeyRevokeParams,
    ) -> Result<serde_json::Value> {
        let registry = linpodx_plugin::KeyRegistry::from_env();
        let publisher = p.publisher.clone();
        registry
            .revoke(&publisher, p.reason.as_deref())
            .map_err(|e| Error::Runtime {
                message: format!("plugin.key_revoke({publisher}) failed: {e}"),
            })?;
        self.audit
            .record(
                AuditSinkKind::PluginKeyRevoked,
                None,
                None,
                serde_json::json!({
                    "publisher": publisher,
                    "reason": p.reason,
                }),
            )
            .await;
        let resp = responses::PluginKeyRevokeResponse {
            publisher,
            revoked: true,
        };
        Ok(serde_json::to_value(resp)?)
    }

    // ----- Phase 17 Stream C — plugin key revoke Raft propagation.
    //
    // When this daemon is the current Raft leader, the request is
    // proposed as an `AppData::RevokePluginKey` entry; the state-machine
    // apply step on every node (including the leader's own follower
    // path) writes the local `.revoked` marker via
    // `KeyRegistry::apply_remote_revocation`. When this daemon is a
    // follower we surface a friendly error pointing at the current
    // leader so the CLI can re-target. A daemon built without Raft
    // returns the same "not_leader"-style error.
    pub(crate) async fn plugin_key_revoke_propagate(
        &self,
        p: linpodx_common::ipc::PluginKeyRevokePropagateParams,
    ) -> Result<serde_json::Value> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            Error::Unsupported(
                "plugin.key_revoke_propagate: raft leader-elect is not enabled \
                 (start daemon with --cluster-raft to use cluster-wide revocation)"
                    .into(),
            )
        })?;
        if !raft.is_leader() {
            let leader = raft
                .current_leader()
                .unwrap_or_else(|| "unknown".to_string());
            return Err(Error::Unavailable(format!(
                "plugin.key_revoke_propagate: not_leader (current_leader={leader}); \
                 re-issue against the leader"
            )));
        }
        let revoked_at = chrono::Utc::now().timestamp();
        let log_index = raft
            .propose_plugin_key_revocation(
                p.publisher.clone(),
                p.fingerprint.clone(),
                p.reason.clone(),
                revoked_at,
            )
            .await
            .map_err(|e| Error::Runtime {
                message: format!("plugin.key_revoke_propagate failed: {e}"),
            })?;
        self.audit
            .record(
                AuditSinkKind::PluginKeyRevokePropagated,
                None,
                None,
                serde_json::json!({
                    "publisher": p.publisher,
                    "fingerprint": p.fingerprint,
                    "reason": p.reason,
                    "log_index": log_index,
                    "revoked_at": revoked_at,
                }),
            )
            .await;
        let resp = responses::PluginKeyRevokePropagateResponse {
            publisher: p.publisher,
            fingerprint: p.fingerprint,
            log_index: Some(log_index),
            propagated: true,
        };
        Ok(serde_json::to_value(resp)?)
    }
}
