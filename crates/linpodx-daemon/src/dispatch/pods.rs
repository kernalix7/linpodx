//! Pod-domain dispatch handlers.

use super::*;
use tracing::info;

impl Dispatcher {
    pub(crate) async fn pod_list(&self) -> Result<serde_json::Value> {
        let pods = linpodx_runtime::pod::pod_list(&self.podman).await?;
        Ok(serde_json::to_value(responses::PodListResponse { pods })?)
    }

    pub(crate) async fn pod_create(
        &self,
        p: linpodx_common::ipc::PodCreateParams,
    ) -> Result<serde_json::Value> {
        let resp = linpodx_runtime::pod::pod_create(&self.podman, &p).await?;
        info!(pod_id = %resp.id, pod_name = %resp.name, "pod created");
        self.publish_with_details(
            EventTopic::Container,
            EventKind::Created,
            resp.id.clone(),
            serde_json::json!({
                "resource_type": "pod",
                "name": resp.name,
                "ports": p.ports,
                "labels": p.labels,
            }),
        );
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn pod_start(
        &self,
        p: linpodx_common::ipc::PodActionParams,
    ) -> Result<serde_json::Value> {
        let resp = linpodx_runtime::pod::pod_start(&self.podman, &p).await?;
        info!(pod_id = %resp.id, status = %resp.status, "pod started");
        self.publish_with_details(
            EventTopic::Container,
            EventKind::Started,
            resp.id.clone(),
            serde_json::json!({
                "resource_type": "pod",
                "id_or_name": p.id_or_name,
                "status": resp.status,
            }),
        );
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn pod_stop(
        &self,
        p: linpodx_common::ipc::PodActionParams,
    ) -> Result<serde_json::Value> {
        let resp = linpodx_runtime::pod::pod_stop(&self.podman, &p).await?;
        info!(pod_id = %resp.id, status = %resp.status, "pod stopped");
        self.publish_with_details(
            EventTopic::Container,
            EventKind::Stopped,
            resp.id.clone(),
            serde_json::json!({
                "resource_type": "pod",
                "id_or_name": p.id_or_name,
                "status": resp.status,
            }),
        );
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn pod_remove(
        &self,
        p: linpodx_common::ipc::PodRemoveParams,
    ) -> Result<serde_json::Value> {
        let resp = linpodx_runtime::pod::pod_remove(&self.podman, &p).await?;
        info!(pod_id = %resp.id, status = %resp.status, force = p.force, "pod removed");
        self.publish_with_details(
            EventTopic::Container,
            EventKind::Removed,
            resp.id.clone(),
            serde_json::json!({
                "resource_type": "pod",
                "id_or_name": p.id_or_name,
                "force": p.force,
                "status": resp.status,
            }),
        );
        Ok(serde_json::to_value(resp)?)
    }
}
