//! Image-domain dispatch handlers (list/pull/remove/inspect/tag, async pull
//! job, registry push + multi-arch manifest).

use super::*;

impl Dispatcher {
    pub(crate) async fn image_list(
        &self,
        p: linpodx_common::ipc::ImageListParams,
    ) -> Result<serde_json::Value> {
        let list = image::list(&self.podman, &p).await?;
        Ok(serde_json::to_value(list)?)
    }

    pub(crate) async fn image_pull(
        &self,
        p: linpodx_common::ipc::ImagePullParams,
    ) -> Result<serde_json::Value> {
        let reference = p.reference.clone();
        let id = image::pull(&self.podman, &p).await?;
        self.publish_with_details(
            EventTopic::Image,
            EventKind::Pulled,
            id.0.clone(),
            serde_json::json!({ "reference": reference }),
        );
        Ok(serde_json::to_value(id)?)
    }

    pub(crate) async fn image_remove(
        &self,
        p: linpodx_common::ipc::ImageRemoveParams,
    ) -> Result<serde_json::Value> {
        let id_str = p.id.0.clone();
        image::remove(&self.podman, &p).await?;
        self.publish(EventTopic::Image, EventKind::Removed, id_str);
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn image_inspect(
        &self,
        p: linpodx_common::ipc::ImageIdParams,
    ) -> Result<serde_json::Value> {
        let inspect = image::inspect(&self.podman, &p.id).await?;
        Ok(serde_json::to_value(inspect)?)
    }

    pub(crate) async fn image_tag(
        &self,
        p: linpodx_common::ipc::ImageTagParams,
    ) -> Result<serde_json::Value> {
        let target = p.target.clone();
        let source = p.source.0.clone();
        image::tag(&self.podman, &p).await?;
        self.publish_with_details(
            EventTopic::Image,
            EventKind::Tagged,
            source,
            serde_json::json!({ "target": target }),
        );
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn image_pull_job(
        &self,
        p: linpodx_common::ipc::ImagePullJobParams,
    ) -> Result<serde_json::Value> {
        let job_id = make_job_id(&p.reference);
        let bus = Arc::clone(&self.event_bus);
        let podman = self.podman.clone();
        let reference = p.reference.clone();
        let job_id_for_task = job_id.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut stream = podman.pull_with_progress(reference.clone());
            let mut had_output = false;
            while let Some(line) = stream.next().await {
                had_output = true;
                bus.publish(Event {
                    topic: EventTopic::Image,
                    kind: EventKind::Progress,
                    resource_id: job_id_for_task.clone(),
                    timestamp: chrono::Utc::now(),
                    details: serde_json::json!({
                        "message": line,
                        "reference": reference,
                    }),
                });
            }
            // The stream closes when the child exits. Without a separate
            // `Child::wait().await.status` we don't have a true exit code,
            // but pulling silently with no progress lines is the only
            // observable failure mode here — flag it so subscribers don't
            // hang waiting for a terminal event.
            let terminal_kind = if had_output {
                EventKind::Succeeded
            } else {
                EventKind::Failed
            };
            bus.publish(Event {
                topic: EventTopic::Image,
                kind: terminal_kind,
                resource_id: job_id_for_task.clone(),
                timestamp: chrono::Utc::now(),
                details: serde_json::json!({ "reference": reference }),
            });
        });
        let payload = serde_json::json!({
            "reference": p.reference,
            "job_id": job_id,
        });
        self.audit
            .record(AuditSinkKind::ImagePullStarted, None, None, payload)
            .await;
        Ok(serde_json::to_value(responses::ImagePullJobResponse {
            job_id,
            status: "started".into(),
        })?)
    }

    pub(crate) async fn image_push(
        &self,
        p: linpodx_common::ipc::ImagePushParams,
    ) -> Result<serde_json::Value> {
        let cert_dir_used = p.cert_dir.clone();
        let resp = image::push(&self.podman, &p).await?;
        let payload = serde_json::json!({
            "reference": resp.reference,
            "digest": resp.digest,
            "registry": p.registry,
            "cert_dir": cert_dir_used.as_ref().map(|p| p.display().to_string()),
        });
        self.audit
            .record(AuditSinkKind::ImagePushed, None, None, payload.clone())
            .await;
        // Phase 14: when an mTLS cert dir was passed, emit a second
        // dedicated audit so operators can isolate registry-mTLS pushes
        // from anonymous / token-auth pushes.
        if cert_dir_used.is_some() {
            self.audit
                .record(AuditSinkKind::ImagePushTls, None, None, payload.clone())
                .await;
        }
        self.publish_with_details(
            EventTopic::Image,
            EventKind::Succeeded,
            resp.reference.clone(),
            payload,
        );
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn image_manifest_create(
        &self,
        p: linpodx_common::ipc::ImageManifestCreateParams,
    ) -> Result<serde_json::Value> {
        let resp = image::manifest_create(&self.podman, &p).await?;
        let payload = serde_json::json!({
            "manifest": resp.manifest,
            "added": resp.added,
        });
        self.audit
            .record(
                AuditSinkKind::ImageManifestCreated,
                None,
                None,
                payload.clone(),
            )
            .await;
        self.publish_with_details(
            EventTopic::Image,
            EventKind::Created,
            resp.manifest.clone(),
            payload,
        );
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn image_manifest_push(
        &self,
        p: linpodx_common::ipc::ImageManifestPushParams,
    ) -> Result<serde_json::Value> {
        let resp = image::manifest_push(&self.podman, &p).await?;
        let payload = serde_json::json!({
            "manifest": resp.manifest,
            "registry": resp.registry,
        });
        // No dedicated AuditSinkKind for manifest push — reuse
        // ImageManifestCreated to keep the manifest's lifecycle in a
        // single audit lane. The payload distinguishes via `registry`.
        self.audit
            .record(
                AuditSinkKind::ImageManifestCreated,
                None,
                None,
                payload.clone(),
            )
            .await;
        self.publish_with_details(
            EventTopic::Image,
            EventKind::Succeeded,
            resp.manifest.clone(),
            payload,
        );
        Ok(serde_json::to_value(resp)?)
    }
}
