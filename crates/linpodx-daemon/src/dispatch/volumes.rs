//! Volume-domain dispatch handlers.

use super::*;

impl Dispatcher {
    pub(crate) async fn volume_list(&self) -> Result<serde_json::Value> {
        let list = volume::list(&self.podman).await?;
        Ok(serde_json::to_value(list)?)
    }

    pub(crate) async fn volume_create(
        &self,
        p: linpodx_common::ipc::VolumeCreateParams,
    ) -> Result<serde_json::Value> {
        let id = volume::create(&self.podman, &p).await?;
        self.publish(EventTopic::Volume, EventKind::Created, id.0.clone());
        Ok(serde_json::to_value(id)?)
    }

    pub(crate) async fn volume_remove(
        &self,
        p: linpodx_common::ipc::VolumeRemoveParams,
    ) -> Result<serde_json::Value> {
        let name = p.name.0.clone();
        volume::remove(&self.podman, &p).await?;
        self.publish(EventTopic::Volume, EventKind::Removed, name);
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn volume_inspect(
        &self,
        p: linpodx_common::ipc::VolumeNameParams,
    ) -> Result<serde_json::Value> {
        let inspect = volume::inspect(&self.podman, &p.name).await?;
        Ok(serde_json::to_value(inspect)?)
    }

    pub(crate) async fn volume_inspect_detail(
        &self,
        p: linpodx_common::ipc::VolumeNameParams,
    ) -> Result<serde_json::Value> {
        let detail = volume::inspect_detail(&self.podman, &p.name).await?;
        Ok(serde_json::to_value(detail)?)
    }

    pub(crate) async fn volume_prune(&self) -> Result<serde_json::Value> {
        let removed = volume::prune(&self.podman).await?;
        for v in &removed {
            self.publish(EventTopic::Volume, EventKind::Removed, v.0.clone());
        }
        Ok(serde_json::to_value(removed)?)
    }
}
