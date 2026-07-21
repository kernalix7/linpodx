//! Sandbox / audit / approval / session dispatch handlers, plus the Phase 17
//! sandbox snapshot auto-trigger toggle.

use super::*;

impl Dispatcher {
    pub(crate) async fn sandbox_profile_list(&self) -> Result<serde_json::Value> {
        let summaries = self.sandbox.list().await;
        Ok(serde_json::to_value(summaries)?)
    }

    pub(crate) async fn sandbox_profile_get(
        &self,
        p: linpodx_common::ipc::SandboxProfileNameParams,
    ) -> Result<serde_json::Value> {
        let resp = self.sandbox.get(&p.name).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn sandbox_profile_reload(&self) -> Result<serde_json::Value> {
        let names = self.sandbox.reload().await?;
        Ok(serde_json::to_value(
            responses::SandboxProfileReloadResponse {
                loaded: names.len(),
                names,
            },
        )?)
    }

    pub(crate) async fn audit_log_query(
        &self,
        p: linpodx_common::ipc::AuditQueryParams,
    ) -> Result<serde_json::Value> {
        let filters = AuditFilters {
            profile_name: p.profile_name,
            kind: p.kind,
            since: p.since.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&chrono::Utc))
            }),
            until: p.until.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&chrono::Utc))
            }),
            limit: p.limit,
        };
        let entries = self.sandbox.query_audit(filters).await?;
        let summaries: Vec<responses::AuditEntrySummary> = entries
            .into_iter()
            .map(|e| responses::AuditEntrySummary {
                seq: e.seq,
                ts: e.ts,
                kind: e.kind,
                profile_name: e.profile_name,
                container_id: e.container_id,
                payload: e.payload,
                prev_hash: e.prev_hash,
                this_hash: e.this_hash,
            })
            .collect();
        Ok(serde_json::to_value(summaries)?)
    }

    pub(crate) async fn audit_log_verify(
        &self,
        p: linpodx_common::ipc::AuditVerifyParams,
    ) -> Result<serde_json::Value> {
        let report = self.sandbox.verify_chain(p.since_seq).await?;
        Ok(serde_json::to_value(responses::AuditVerifyResponse {
            total: report.total,
            last_seq: report.last_seq,
            broken_at: report.broken_at,
        })?)
    }

    pub(crate) async fn approval_decision(
        &self,
        p: linpodx_common::ipc::ApprovalDecisionParams,
    ) -> Result<serde_json::Value> {
        let outcome = if p.allow {
            ApprovalOutcome::Granted {
                by: p.by.unwrap_or_else(|| "unknown".into()),
                reason: p.reason,
            }
        } else {
            ApprovalOutcome::Denied {
                by: p.by.unwrap_or_else(|| "unknown".into()),
                reason: p.reason,
            }
        };
        let accepted = self.approvals.respond(&p.request_id, outcome);
        Ok(serde_json::to_value(responses::ApprovalDecisionResponse {
            accepted,
        })?)
    }

    // ApprovalsSubscribe is intercepted at the server layer (see server.rs);
    // reaching this arm would be a server bug.
    pub(crate) async fn approvals_subscribe_unsupported(&self) -> Result<serde_json::Value> {
        Err(Error::Internal(
            "ApprovalsSubscribe must be handled at the server layer, not dispatch".into(),
        ))
    }

    pub(crate) async fn session_list(
        &self,
        p: linpodx_common::ipc::SessionListParams,
    ) -> Result<serde_json::Value> {
        let summaries = self
            .session
            .list(p.container_id.as_deref(), p.limit)
            .await?;
        Ok(serde_json::to_value(summaries)?)
    }

    pub(crate) async fn session_inspect(
        &self,
        p: linpodx_common::ipc::SessionIdParams,
    ) -> Result<serde_json::Value> {
        let summary = self.session.inspect(p.id).await?;
        Ok(serde_json::to_value(summary)?)
    }

    pub(crate) async fn session_timeline(
        &self,
        p: linpodx_common::ipc::SessionTimelineParams,
    ) -> Result<serde_json::Value> {
        let entries = self.session.timeline(p.id, &p.kinds).await?;
        Ok(serde_json::to_value(entries)?)
    }

    // ----- Phase 17 Stream B — sandbox snapshot auto-trigger toggle / status.
    //
    // The hook is wired by main.rs after the daemon resolves a
    // snapshot encryption config. If a daemon is started without
    // encryption configured (no `LINPODX_SNAPSHOT_*` env vars and no
    // CLI override) the hook stays absent and these arms return a
    // friendly Runtime error rather than crashing.
    pub(crate) async fn sandbox_snapshot_auto_trigger_status(&self) -> Result<serde_json::Value> {
        match self.sandbox.auto_encrypt_hook() {
            Some(hook) => {
                let st = hook.status().await;
                let resp = responses::SandboxSnapshotAutoTriggerStatusResponse {
                    enabled: st.enabled,
                    last_image_ref: st.last_image_ref,
                    trigger_count: st.trigger_count,
                };
                Ok(serde_json::to_value(resp)?)
            }
            None => Err(Error::Unsupported(
                "sandbox.snapshot_auto_trigger: hook not wired \
                 (daemon started without snapshot encryption)"
                    .into(),
            )),
        }
    }

    pub(crate) async fn sandbox_snapshot_auto_trigger_enable(
        &self,
        p: linpodx_common::ipc::SandboxSnapshotAutoTriggerEnableParams,
    ) -> Result<serde_json::Value> {
        match self.sandbox.auto_encrypt_hook() {
            Some(hook) => {
                let previous = hook.set_enabled(p.enabled);
                let st = hook.status().await;
                let resp = responses::SandboxSnapshotAutoTriggerStatusResponse {
                    enabled: st.enabled,
                    last_image_ref: st.last_image_ref,
                    trigger_count: st.trigger_count,
                };
                tracing::info!(previous, now = p.enabled, "sandbox auto-encrypt toggle");
                Ok(serde_json::to_value(resp)?)
            }
            None => Err(Error::Unsupported(
                "sandbox.snapshot_auto_trigger: hook not wired \
                 (daemon started without snapshot encryption)"
                    .into(),
            )),
        }
    }
}
