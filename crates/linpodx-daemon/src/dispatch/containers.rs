//! Container-domain dispatch handlers.
//!
//! Each handler is one arm of the former monolithic `handle_method` match,
//! moved verbatim into a `pub(crate)` method on [`super::Dispatcher`]. The
//! router in `dispatch.rs` calls these by name.

use super::*;

impl Dispatcher {
    pub(crate) async fn version(&self) -> Result<serde_json::Value> {
        let resp = responses::VersionResponse {
            linpodx_version: LINPODX_VERSION.to_string(),
            ipc_version: IPC_VERSION,
            podman_version: self.podman_version.clone(),
        };
        Ok(serde_json::to_value(resp)?)
    }

    // Subscribe is intercepted by the server layer (see server.rs); reaching this
    // arm would be a server bug.
    pub(crate) async fn subscribe_unsupported(&self) -> Result<serde_json::Value> {
        Err(Error::Internal(
            "Subscribe must be handled at the server layer, not dispatch".into(),
        ))
    }

    pub(crate) async fn container_list(
        &self,
        p: linpodx_common::ipc::ContainerListParams,
    ) -> Result<serde_json::Value> {
        let list = self.podman.list(p.all).await?;
        Ok(serde_json::to_value(list)?)
    }

    pub(crate) async fn container_create(
        &self,
        mut opts: linpodx_common::ipc::CreateOptions,
    ) -> Result<serde_json::Value> {
        // Phase 1C: if a sandbox profile is named, apply policy first.
        let profile_name_for_session = opts.sandbox_profile.clone();
        if let Some(profile_name) = opts.sandbox_profile.clone() {
            let (transformed, _applied) = self.sandbox.apply_to_create(&profile_name, opts).await?;
            opts = transformed;
        }
        // Phase 13: optional `runtime_injector` plugin chain. Runs *after*
        // `apply_to_create` so plugins see the post-policy CreateOptions and
        // can append (never override) env / args / security_opts. Each call
        // emits a single `PluginRuntimeInjectorCalled` audit entry.
        if let Some(registry) = self.plugin_registry.clone() {
            let opts_json = serde_json::to_vec(&opts)?;
            let payload = match tokio::task::spawn_blocking(move || {
                let mut guard = registry.blocking_write();
                guard.evaluate_runtime_injector(&opts_json)
            })
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "runtime_injector task join failed; skipping injector");
                    linpodx_plugin::InjectorPayload::default()
                }
            };
            if !payload.is_empty() {
                self.audit
                    .record(
                        AuditSinkKind::PluginRuntimeInjectorCalled,
                        profile_name_for_session.clone(),
                        None,
                        serde_json::json!({
                            "env_add": payload.env_add.len(),
                            "args_append": payload.args_append.len(),
                            "security_opts_add": payload.security_opts_add.len(),
                        }),
                    )
                    .await;
                opts.env.extend(payload.env_add);
                opts.command.extend(payload.args_append);
                opts.security_opts.extend(payload.security_opts_add);
            }
        }
        // Phase 10: promote the Phase 9 audit-only overlayfs hook to actual
        // rootfs injection. When OverlayfsBackend has a live fuse-overlayfs
        // mount for this image (created by an earlier snapshot commit), pass
        // it to podman as --rootfs and drop the image positional. The audit
        // entry below still fires so the linkage is visible in the chain.
        let mounted_rootfs =
            OverlayfsBackend::mount_path_for(&opts.image).map(|p| p.display().to_string());
        if let Some(rootfs_path) = mounted_rootfs.as_ref() {
            opts.rootfs = Some(rootfs_path.clone());
        }
        let id = self.podman.create(&opts).await?;
        let container_name = opts.name.clone().unwrap_or_else(|| id.0.clone());
        // Phase 2C: open a session row for the container's lifetime.
        if let Err(e) = self
            .session
            .start(&id.0, &container_name, profile_name_for_session.as_deref())
            .await
        {
            warn!(error = %e, container = %id.0, "session::start failed (non-fatal)");
        }
        // Phase 2B: optional pre-run snapshot when the profile asks for it.
        if let Some(profile_name) = &profile_name_for_session {
            match self
                .sandbox
                .pre_run_snapshot(&self.podman, profile_name, &id)
                .await
            {
                Ok(Some(snap_id)) => {
                    tracing::info!(snap_id, container = %id.0, "pre-run snapshot taken");
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(error = %e, container = %id.0, "pre-run snapshot failed (non-fatal)");
                }
            }
        }
        // Phase 10: when an overlayfs mount was promoted to --rootfs above,
        // record an informational audit entry so the linkage between the
        // snapshot, the mount path and the new container is visible in the
        // hash-chained log.
        if let Some(rootfs_path) = mounted_rootfs.as_ref() {
            let payload = serde_json::json!({
                "container_id": id.0,
                "image": opts.image,
                "mount_path": rootfs_path,
            });
            self.audit
                .record(
                    AuditSinkKind::SnapshotMounted,
                    profile_name_for_session.clone(),
                    Some(id.0.clone()),
                    payload,
                )
                .await;
        }
        self.publish_with_details(
            EventTopic::Container,
            EventKind::Created,
            id.0.clone(),
            serde_json::json!({
                "image": opts.image,
                "name": opts.name,
                "sandbox_profile": opts.sandbox_profile,
            }),
        );
        Ok(serde_json::to_value(id)?)
    }

    pub(crate) async fn container_start(
        &self,
        p: linpodx_common::ipc::ContainerIdParams,
    ) -> Result<serde_json::Value> {
        self.podman.start(&p.id).await?;
        let id_str = p.id.0.clone();
        self.metrics.spawn_for(id_str.clone()).await;
        self.publish(EventTopic::Container, EventKind::Started, id_str);
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn container_stop(
        &self,
        p: linpodx_common::ipc::ContainerStopParams,
    ) -> Result<serde_json::Value> {
        let timeout = p.timeout_secs.map(|s| Duration::from_secs(s as u64));
        self.podman.stop(&p.id, timeout).await?;
        let id_str = p.id.0.clone();
        self.metrics.stop_for(&id_str).await;
        self.publish(EventTopic::Container, EventKind::Stopped, id_str);
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn container_remove(
        &self,
        p: linpodx_common::ipc::ContainerRemoveParams,
    ) -> Result<serde_json::Value> {
        // Resolve the user-supplied id/name to the canonical container id so the session
        // row (keyed by full id) closes correctly when the user passed a name.
        let canonical_id = match self.podman.inspect(&p.id).await {
            Ok(insp) => insp.id.0,
            Err(_) => p.id.0.clone(),
        };
        self.podman.remove(&p.id, p.force).await?;
        self.metrics.stop_for(&canonical_id).await;
        if let Err(e) = self.session.end(&canonical_id).await {
            warn!(error = %e, container = %canonical_id, "session::end failed (non-fatal)");
        }
        self.publish(EventTopic::Container, EventKind::Removed, canonical_id);
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn container_inspect(
        &self,
        p: linpodx_common::ipc::ContainerIdParams,
    ) -> Result<serde_json::Value> {
        let inspect = self.podman.inspect(&p.id).await?;
        Ok(serde_json::to_value(inspect)?)
    }

    pub(crate) async fn container_logs(
        &self,
        p: linpodx_common::ipc::ContainerLogsParams,
    ) -> Result<serde_json::Value> {
        let logs = self
            .podman
            .logs(&p.id, LogOptions { since: p.since })
            .await?;
        Ok(serde_json::to_value(responses::LogsResponse {
            stdout: logs.stdout,
            stderr: logs.stderr,
        })?)
    }

    pub(crate) async fn container_exec(
        &self,
        p: linpodx_common::ipc::ContainerExecParams,
    ) -> Result<serde_json::Value> {
        let cid = ContainerId::new(p.container_id.clone());
        let opts = ExecOptions {
            id: cid,
            command: p.command.clone(),
            env: p.env.clone(),
            tty: p.tty,
        };
        let out = self.podman.exec(opts).await?;
        let payload = serde_json::json!({
            "container_id": p.container_id,
            "command": p.command,
            "exit_code": out.exit_code,
        });
        self.audit
            .record(
                AuditSinkKind::ContainerExecCalled,
                None,
                Some(p.container_id.clone()),
                payload,
            )
            .await;
        Ok(serde_json::to_value(responses::ContainerExecResponse {
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
        })?)
    }

    pub(crate) async fn container_logs_stream(
        &self,
        p: linpodx_common::ipc::ContainerLogsStreamParams,
    ) -> Result<serde_json::Value> {
        let cid = ContainerId::new(p.container_id.clone());
        let bus = Arc::clone(&self.event_bus);
        let podman = self.podman.clone();
        let container_id = p.container_id.clone();
        let follow = p.follow;
        let since = p.since.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut stream = podman.logs_stream(&cid, follow, since);
            while let Some((kind, line)) = stream.next().await {
                bus.publish(Event {
                    topic: EventTopic::Container,
                    kind: EventKind::Log,
                    resource_id: container_id.clone(),
                    timestamp: chrono::Utc::now(),
                    details: serde_json::json!({
                        "stream": kind.as_str(),
                        "line": line,
                    }),
                });
            }
        });
        let payload = serde_json::json!({
            "container_id": p.container_id,
            "follow": p.follow,
            "since": p.since,
        });
        self.audit
            .record(
                AuditSinkKind::ContainerLogsStreamed,
                None,
                Some(p.container_id.clone()),
                payload,
            )
            .await;
        Ok(serde_json::to_value(
            responses::ContainerLogsStreamResponse {
                started: true,
                container_id: p.container_id,
            },
        )?)
    }

    pub(crate) async fn container_exec_pty(
        &self,
        p: linpodx_common::ipc::ContainerExecPtyParams,
    ) -> Result<serde_json::Value> {
        if p.command.is_empty() {
            return Err(Error::InvalidArgument(
                "container_exec_pty: command must not be empty".into(),
            ));
        }
        let cid = ContainerId::new(p.container_id.clone());
        let opts = PtyExecOptions {
            container_id: cid,
            command: p.command.clone(),
            env: p.env.clone(),
            cols: p.cols.unwrap_or(80),
            rows: p.rows.unwrap_or(24),
            podman_bin: self.podman_bin.clone(),
        };
        let handle = linpodx_runtime::exec_pty(opts).await?;
        let bridge_id = handle.bridge_id.clone();
        let endpoint = format!("/pty/{bridge_id}");
        {
            let mut map = self.pty_handles.lock().await;
            map.insert(bridge_id.clone(), handle);
        }
        let payload = serde_json::json!({
            "container_id": p.container_id,
            "bridge_id": bridge_id,
            "endpoint": endpoint,
            "cols": p.cols.unwrap_or(80),
            "rows": p.rows.unwrap_or(24),
        });
        self.audit
            .record(
                AuditSinkKind::ContainerExecPtyOpened,
                None,
                Some(p.container_id.clone()),
                payload,
            )
            .await;
        Ok(serde_json::to_value(responses::ContainerExecPtyResponse {
            bridge_id,
            endpoint,
        })?)
    }
}
