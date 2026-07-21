//! Network-domain dispatch handlers (CRUD + Phase 5 L4 egress firewall apply).

use super::*;

impl Dispatcher {
    pub(crate) async fn network_list(&self) -> Result<serde_json::Value> {
        let list = network::list(&self.podman).await?;
        Ok(serde_json::to_value(list)?)
    }

    pub(crate) async fn network_create(
        &self,
        p: linpodx_common::ipc::NetworkCreateParams,
    ) -> Result<serde_json::Value> {
        let id = network::create(&self.podman, &p).await?;
        self.publish(EventTopic::Network, EventKind::Created, id.0.clone());
        Ok(serde_json::to_value(id)?)
    }

    pub(crate) async fn network_remove(
        &self,
        p: linpodx_common::ipc::NetworkRemoveParams,
    ) -> Result<serde_json::Value> {
        let name = p.name.0.clone();
        network::remove(&self.podman, &p).await?;
        self.publish(EventTopic::Network, EventKind::Removed, name);
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn network_inspect(
        &self,
        p: linpodx_common::ipc::NetworkNameParams,
    ) -> Result<serde_json::Value> {
        let inspect = network::inspect(&self.podman, &p.name).await?;
        Ok(serde_json::to_value(inspect)?)
    }

    pub(crate) async fn network_prune(&self) -> Result<serde_json::Value> {
        let removed = network::prune(&self.podman).await?;
        for n in &removed {
            self.publish(EventTopic::Network, EventKind::Removed, n.0.clone());
        }
        Ok(serde_json::to_value(removed)?)
    }

    pub(crate) async fn network_egress_apply(
        &self,
        p: linpodx_common::ipc::NetworkEgressApplyParams,
    ) -> Result<serde_json::Value> {
        let inspect = self
            .podman
            .inspect(&ContainerId::from(p.container_id.clone()))
            .await?;
        let pid = inspect
            .raw
            .as_ref()
            .and_then(|raw| raw.get("State"))
            .and_then(|s| s.get("Pid"))
            .and_then(|v| v.as_u64())
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::Runtime {
                message: format!(
                    "container '{}' has no live PID (not running?)",
                    p.container_id
                ),
            })? as u32;
        let enforcer = EgressEnforcer::from_env();
        // Stage 3 wire-up: pull the L4 allowlist from the sandbox profile that
        // was attached to this container's session at create time. When no
        // session row exists or no profile is attached, the rule vec is empty
        // and the helper installs only the base drop-by-default table.
        let rules = match self.session.profile_for_container(&inspect.id.0).await {
            Ok(Some(profile)) => self.sandbox.l4_rules_for_profile(&profile).await,
            _ => Vec::new(),
        };
        let rules_requested = rules.len();
        let (helper_applied, applied_count) =
            enforcer
                .apply(pid, rules)
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("egress helper apply failed: {e}"),
                })?;
        let resp = responses::NetworkEgressApplyResponse {
            container_id: inspect.id.0.clone(),
            helper_applied,
            rules_applied: if helper_applied {
                applied_count
            } else {
                rules_requested
            },
        };
        Ok(serde_json::to_value(resp)?)
    }
}
