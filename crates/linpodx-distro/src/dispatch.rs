//! Self-contained dispatch helper for the daemon's six `Method::Distro*` arms.
//!
//! The daemon's `Dispatcher` struct is owned by platform/qa and we don't touch it during
//! Stage 2-B. Instead, this module exposes [`handle`], a single async entry point that
//! takes the same set of `Arc`s the daemon already passes around (database via the
//! sandbox-team's `SnapshotManager::database`, `AuditSink`, `EventPublisher`, `Podman`)
//! and returns a serialized `serde_json::Value` for the JSON-RPC response.
//!
//! `Dispatcher` holds an `Arc<SnapshotManager>` already; the six arms in `dispatch.rs`
//! borrow `&self` and call `handle(...)` with whatever they have on hand.

use crate::instance::InstanceManager;
use crate::registry::Registry;
use crate::{BuildSpec, DistroError, Result};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{
    responses::{
        DistroBuildResponse, DistroTemplateInspectResponse, DistroTemplateListResponse,
        DistroTemplateSummary,
    },
    DistroBuildParams, DistroCreateParams, DistroEnterParams, DistroRemoveParams,
    DistroTemplateInspectParams,
};
use linpodx_runtime::Podman;
use std::sync::Arc;

/// Available actions wrapped in one enum so the daemon can route a single call.
pub enum DistroAction {
    TemplateList,
    TemplateInspect(DistroTemplateInspectParams),
    Create(DistroCreateParams),
    Build(DistroBuildParams),
    Enter(DistroEnterParams),
    Remove(DistroRemoveParams),
}

/// Top-level handler used by `linpodx-daemon::dispatch`. Returns a serialized JSON value
/// suitable for stuffing into `RpcResponse::success(_, value)`.
///
/// `db` / `publisher` / `audit` are shared infrastructure handles already constructed by
/// the daemon. `podman` is the runtime adapter; `podman_bin` is the binary path used for
/// the `Build` action (which spawns `podman build` directly, since the runtime adapter
/// doesn't expose a build helper yet).
pub async fn handle(
    action: DistroAction,
    podman: &Podman,
    podman_bin: &str,
    db: Arc<Database>,
    publisher: Arc<dyn EventPublisher>,
    audit: Arc<dyn AuditSink>,
) -> Result<serde_json::Value> {
    match action {
        DistroAction::TemplateList => {
            let summaries: DistroTemplateListResponse = Registry::list()
                .into_iter()
                .map(|t| DistroTemplateSummary {
                    kind: t.kind,
                    display_name: t.display_name,
                    default_image: t.default_image,
                    init_kind: t.init_kind.as_str().to_string(),
                    default_packages: t.default_packages,
                })
                .collect();
            Ok(serde_json::to_value(summaries)?)
        }
        DistroAction::TemplateInspect(params) => {
            let t = Registry::inspect(params.kind);
            let resp = DistroTemplateInspectResponse {
                kind: t.kind,
                display_name: t.display_name,
                default_image: t.default_image,
                init_kind: t.init_kind.as_str().to_string(),
                default_packages: t.default_packages,
                recommended_passthrough: t.recommended_passthrough,
                default_shell: t.default_shell,
                notes: t.notes,
            };
            Ok(serde_json::to_value(resp)?)
        }
        DistroAction::Create(params) => {
            let mgr = InstanceManager::new(db, publisher, audit.clone());
            let resp = mgr.create(podman, &params).await?;
            // Best-effort menu entry creation if the user asked for one via passthrough.
            if let Some(label) = params
                .passthrough
                .as_ref()
                .and_then(|p| p.register_app_menu.clone())
            {
                let exec_cmd = vec![
                    "podman".to_string(),
                    "exec".into(),
                    "-it".into(),
                    resp.instance.container_id.clone(),
                    Registry::inspect(resp.instance.kind).default_shell,
                ];
                if let Err(e) = crate::menu::write_desktop_entry(&label, &exec_cmd, None) {
                    tracing::warn!(error = %e, label, "write_desktop_entry failed (non-fatal)");
                }
                audit
                    .record(
                        AuditSinkKind::PassthroughGranted,
                        None,
                        Some(resp.instance.container_id.clone()),
                        serde_json::json!({"register_app_menu": label}),
                    )
                    .await;
            }
            Ok(serde_json::to_value(resp)?)
        }
        DistroAction::Build(params) => {
            let spec = BuildSpec {
                kind: params.kind,
                base_tag: params.base_tag,
                include: params.include,
            };
            let (image_ref, duration_ms) = spec.build(podman_bin, None, None).await?;
            audit
                .record(
                    AuditSinkKind::DistroBuilt,
                    None,
                    None,
                    serde_json::json!({
                        "kind": params.kind.as_str(),
                        "image_ref": image_ref,
                        "duration_ms": duration_ms,
                    }),
                )
                .await;
            Ok(serde_json::to_value(DistroBuildResponse {
                image_ref,
                duration_ms,
            })?)
        }
        DistroAction::Enter(params) => {
            let mgr = InstanceManager::new(db, publisher, audit);
            let resp = mgr.enter(&params.name).await?;
            Ok(serde_json::to_value(resp)?)
        }
        DistroAction::Remove(params) => {
            let mgr = InstanceManager::new(db, publisher, audit);
            let resp = mgr.remove(podman, &params.name, params.keep_volume).await?;
            Ok(serde_json::to_value(resp)?)
        }
    }
}

/// Map our crate-local error onto `linpodx_common::error::Error` so the daemon can
/// re-use its existing `error_to_code` switch.
impl From<DistroError> for linpodx_common::error::Error {
    fn from(e: DistroError) -> Self {
        match e {
            DistroError::NotFound(s) => linpodx_common::error::Error::NotFound(s),
            DistroError::NameTaken(s) => linpodx_common::error::Error::InvalidArgument(format!(
                "distro instance name '{s}' already in use"
            )),
            DistroError::Io(io) => linpodx_common::error::Error::Io(io),
            DistroError::Db(e) => linpodx_common::error::Error::Sqlx(e),
            DistroError::Serde(e) => linpodx_common::error::Error::Json(e),
            DistroError::Runtime(m) => linpodx_common::error::Error::Runtime { message: m },
            DistroError::NotImplemented(m) => linpodx_common::error::Error::Runtime {
                message: format!("not implemented: {m}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::NoopAuditSink;
    use linpodx_common::events::NoopEventPublisher;

    async fn fresh_db() -> Arc<Database> {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("dispatch-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        Arc::new(db)
    }

    #[tokio::test]
    async fn template_list_returns_six() {
        let db = fresh_db().await;
        let podman = Podman::default();
        let value = handle(
            DistroAction::TemplateList,
            &podman,
            "podman",
            db,
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        )
        .await
        .unwrap();
        let summaries: DistroTemplateListResponse = serde_json::from_value(value).unwrap();
        assert_eq!(summaries.len(), 6);
    }

    #[tokio::test]
    async fn template_inspect_alpine_returns_openrc() {
        let db = fresh_db().await;
        let podman = Podman::default();
        let value = handle(
            DistroAction::TemplateInspect(DistroTemplateInspectParams {
                kind: linpodx_common::passthrough::DistroKind::Alpine,
            }),
            &podman,
            "podman",
            db,
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        )
        .await
        .unwrap();
        let resp: DistroTemplateInspectResponse = serde_json::from_value(value).unwrap();
        assert_eq!(resp.init_kind, "openrc");
        assert_eq!(resp.default_shell, "ash");
    }

    #[tokio::test]
    async fn enter_unknown_maps_to_not_found() {
        let db = fresh_db().await;
        let podman = Podman::default();
        let err = handle(
            DistroAction::Enter(DistroEnterParams {
                name: "missing".into(),
            }),
            &podman,
            "podman",
            db,
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        )
        .await
        .unwrap_err();
        let common: linpodx_common::error::Error = err.into();
        assert!(matches!(common, linpodx_common::error::Error::NotFound(_)));
    }
}
