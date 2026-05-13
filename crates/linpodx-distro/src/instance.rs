//! Distro instance lifecycle.
//!
//! Maps `DistroCreate` / `DistroEnter` / `DistroRemove` IPC requests onto Podman
//! container operations and the `distro_instances` SQLite table.
//!
//! `vm_mode` flips the instance from ephemeral (one-off shell) into a long-lived box:
//! * a persistent home volume is created and mounted at `/home/linpodx`
//! * `--restart=unless-stopped` is set so the container survives reboots
//! * `--userns=keep-id` maps host UID/GID 1:1 so files written inside `/home/linpodx`
//!   are owned by the host user from outside the container.

use crate::registry::Registry;
use crate::templates::{InitKind, TemplateMeta};
use crate::{DistroError, Result};
use chrono::{DateTime, Utc};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use linpodx_common::error::Error as CommonError;
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{
    responses::{
        DistroCreateResponse, DistroEnterResponse, DistroInstanceSummary, DistroRemoveResponse,
    },
    CreateOptions, DistroCreateParams, Event, EventKind, EventTopic, VolumeCreateParams,
    VolumeRemoveParams,
};
use linpodx_common::passthrough::{DistroKind, PassthroughSpec};
use linpodx_common::types::{ContainerId, VolumeId};
use linpodx_runtime::{volume as rt_volume, Podman};
use std::sync::Arc;
use tracing::{info, instrument, warn};

const HOME_PATH_IN_CONTAINER: &str = "/home/linpodx";
const TS_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

pub struct InstanceManager {
    db: Arc<Database>,
    publisher: Arc<dyn EventPublisher>,
    audit: Arc<dyn AuditSink>,
}

impl InstanceManager {
    pub fn new(
        db: Arc<Database>,
        publisher: Arc<dyn EventPublisher>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            db,
            publisher,
            audit,
        }
    }

    /// Create + start a distro instance, recording the row in `distro_instances`.
    #[instrument(skip(self, podman), fields(name = %params.name, kind = %params.kind))]
    pub async fn create(
        &self,
        podman: &Podman,
        params: &DistroCreateParams,
    ) -> Result<DistroCreateResponse> {
        validate_instance_name(&params.name)?;
        if let Some(existing) = self.lookup_active_row(&params.name).await? {
            return Err(DistroError::NameTaken(existing.name));
        }

        let template = Registry::inspect(params.kind);
        let image_ref = params
            .custom_image
            .clone()
            .unwrap_or_else(|| template.default_image.clone());

        // Provision the persistent home volume up-front for VM mode so the row we insert
        // can name it.
        let home_volume = if params.vm_mode {
            let vol_name = format!("linpodx-distro-{}-home", params.name);
            create_volume_if_missing(podman, &vol_name).await?;
            Some(vol_name)
        } else {
            None
        };

        let opts = build_create_options(&template, params, &image_ref, home_volume.as_deref());

        let container_id = podman
            .create(&opts)
            .await
            .map_err(|e| DistroError::Runtime(e.to_string()))?;

        if let Err(e) = podman.start(&container_id).await {
            // Roll back the just-created container so we don't leave dangling resources.
            warn!(error = %e, container_id = %container_id.0, "podman start failed; cleaning up");
            let _ = podman.remove(&container_id, true).await;
            if let Some(name) = &home_volume {
                let _ = best_effort_remove_volume(podman, name).await;
            }
            return Err(DistroError::Runtime(e.to_string()));
        }

        let now = Utc::now();
        let now_str = now.format(TS_FORMAT).to_string();
        let auto_restart = params.vm_mode;

        let row: (i64,) = sqlx::query_as(
            "INSERT INTO distro_instances (name, kind, container_id, image_ref, vm_mode, \
             home_volume, auto_restart, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&params.name)
        .bind(params.kind.as_str())
        .bind(&container_id.0)
        .bind(&image_ref)
        .bind(params.vm_mode as i64)
        .bind(home_volume.as_deref())
        .bind(auto_restart as i64)
        .bind(&now_str)
        .fetch_one(self.db.pool())
        .await
        .map_err(DistroError::Db)?;
        let id = row.0;

        let summary = DistroInstanceSummary {
            id,
            name: params.name.clone(),
            kind: params.kind,
            container_id: container_id.0.clone(),
            image_ref: image_ref.clone(),
            vm_mode: params.vm_mode,
            home_volume: home_volume.clone(),
            auto_restart,
            created_at: now,
        };

        self.audit
            .record(
                AuditSinkKind::DistroCreated,
                params.sandbox_profile.clone(),
                Some(container_id.0.clone()),
                serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
            )
            .await;
        self.publisher.publish(Event {
            topic: EventTopic::Distro,
            kind: EventKind::Created,
            resource_id: params.name.clone(),
            timestamp: Utc::now(),
            details: serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        });
        info!(instance_id = id, container = %container_id.0, "distro instance created");
        Ok(DistroCreateResponse { instance: summary })
    }

    /// Look up an instance by name and return the suggested `podman exec -it` command.
    #[instrument(skip(self))]
    pub async fn enter(&self, name: &str) -> Result<DistroEnterResponse> {
        let row = self
            .lookup_active_row(name)
            .await?
            .ok_or_else(|| DistroError::NotFound(name.to_string()))?;
        let template = Registry::inspect(row.kind_parsed()?);
        let mut suggested = vec!["podman".to_string(), "exec".to_string(), "-it".to_string()];
        if row.vm_mode {
            // keep-id maps host UID/GID, so use the same user inside.
            if let Ok(uid) = std::env::var("UID").or_else(|_| {
                // tokio doesn't expose `getuid` portably; libc is fine but adds a dep.
                // Fall back to env var or whoami crate-free heuristic.
                std::env::var("USER").map(|_| String::new())
            }) {
                if !uid.is_empty() {
                    suggested.push("-u".into());
                    suggested.push(uid);
                }
            }
        }
        suggested.push(row.container_id.clone());
        suggested.push(template.default_shell.clone());

        self.audit
            .record(
                AuditSinkKind::DistroEntered,
                None,
                Some(row.container_id.clone()),
                serde_json::json!({ "name": row.name, "shell": template.default_shell }),
            )
            .await;
        self.publisher.publish(Event {
            topic: EventTopic::Distro,
            kind: EventKind::Started,
            resource_id: row.name.clone(),
            timestamp: Utc::now(),
            details: serde_json::json!({ "container_id": row.container_id }),
        });
        Ok(DistroEnterResponse {
            container_id: row.container_id,
            suggested_command: suggested,
        })
    }

    /// Stop + remove the container and (optionally) its persistent volume.
    #[instrument(skip(self, podman))]
    pub async fn remove(
        &self,
        podman: &Podman,
        name: &str,
        keep_volume: bool,
    ) -> Result<DistroRemoveResponse> {
        let row = self
            .lookup_active_row(name)
            .await?
            .ok_or_else(|| DistroError::NotFound(name.to_string()))?;
        let cid = ContainerId::new(row.container_id.clone());
        if let Err(e) = podman
            .stop(&cid, Some(std::time::Duration::from_secs(5)))
            .await
        {
            // Stopping a not-running container is fine; only log other failures.
            warn!(error = %e, container = %cid.0, "stop failed during distro remove (continuing)");
        }
        if let Err(e) = podman.remove(&cid, true).await {
            // The container may have already been removed out-of-band; if so we still
            // want the row marked removed.
            warn!(error = %e, container = %cid.0, "remove failed during distro remove");
        }

        let kept_volume = if let Some(vol) = &row.home_volume {
            if keep_volume {
                true
            } else {
                if let Err(e) = best_effort_remove_volume(podman, vol).await {
                    warn!(error = %e, volume = %vol, "removing home volume failed; leaving in place");
                }
                false
            }
        } else {
            // No volume to begin with — `kept_volume` reflects "did we keep one?"; false.
            false
        };

        let now = Utc::now().format(TS_FORMAT).to_string();
        sqlx::query("UPDATE distro_instances SET removed_at = ? WHERE id = ?")
            .bind(&now)
            .bind(row.id)
            .execute(self.db.pool())
            .await
            .map_err(DistroError::Db)?;

        // Best-effort menu entry cleanup.
        if let Err(e) = crate::menu::remove_desktop_entry(name) {
            warn!(error = %e, "remove_desktop_entry failed (non-fatal)");
        }

        self.audit
            .record(
                AuditSinkKind::DistroRemoved,
                None,
                Some(row.container_id.clone()),
                serde_json::json!({ "name": row.name, "kept_volume": kept_volume }),
            )
            .await;
        self.publisher.publish(Event {
            topic: EventTopic::Distro,
            kind: EventKind::Removed,
            resource_id: row.name.clone(),
            timestamp: Utc::now(),
            details: serde_json::json!({ "kept_volume": kept_volume }),
        });
        Ok(DistroRemoveResponse {
            name: row.name,
            kept_volume,
        })
    }

    /// List every active (not-yet-removed) instance, newest first.
    #[instrument(skip(self))]
    pub async fn list(&self) -> Result<Vec<DistroInstanceSummary>> {
        let rows: Vec<DistroRow> = sqlx::query_as::<_, DistroRow>(
            "SELECT id, name, kind, container_id, image_ref, vm_mode, home_volume, \
             auto_restart, created_at, removed_at \
             FROM distro_instances WHERE removed_at IS NULL ORDER BY id DESC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(DistroError::Db)?;
        rows.into_iter().map(DistroRow::into_summary).collect()
    }

    async fn lookup_active_row(&self, name: &str) -> Result<Option<DistroRow>> {
        let row = sqlx::query_as::<_, DistroRow>(
            "SELECT id, name, kind, container_id, image_ref, vm_mode, home_volume, \
             auto_restart, created_at, removed_at \
             FROM distro_instances WHERE name = ? AND removed_at IS NULL",
        )
        .bind(name)
        .fetch_optional(self.db.pool())
        .await
        .map_err(DistroError::Db)?;
        Ok(row)
    }
}

#[derive(sqlx::FromRow, Clone, Debug)]
struct DistroRow {
    id: i64,
    name: String,
    kind: String,
    container_id: String,
    image_ref: String,
    vm_mode: bool,
    home_volume: Option<String>,
    auto_restart: bool,
    created_at: String,
    #[allow(dead_code)]
    removed_at: Option<String>,
}

impl DistroRow {
    fn kind_parsed(&self) -> Result<DistroKind> {
        DistroKind::parse(&self.kind).map_err(DistroError::Runtime)
    }

    fn into_summary(self) -> Result<DistroInstanceSummary> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                DistroError::Runtime(format!(
                    "invalid distro created_at '{}': {e}",
                    self.created_at
                ))
            })?;
        let kind = self.kind_parsed()?;
        Ok(DistroInstanceSummary {
            id: self.id,
            name: self.name,
            kind,
            container_id: self.container_id,
            image_ref: self.image_ref,
            vm_mode: self.vm_mode,
            home_volume: self.home_volume,
            auto_restart: self.auto_restart,
            created_at,
        })
    }
}

fn build_create_options(
    template: &TemplateMeta,
    params: &DistroCreateParams,
    image_ref: &str,
    home_volume: Option<&str>,
) -> CreateOptions {
    let container_name = format!("linpodx-distro-{}", params.name);
    let mut volumes = Vec::new();
    if let Some(vol) = home_volume {
        volumes.push(linpodx_common::state::VolumeMount {
            source: vol.to_string(),
            destination: HOME_PATH_IN_CONTAINER.into(),
            read_only: false,
        });
    }
    let passthrough = merge_passthrough(&template.recommended_passthrough, &params.passthrough);
    let systemd = matches!(template.init_kind, InitKind::Systemd);
    let labels = vec![
        ("io.linpodx.distro".into(), template.kind.as_str().into()),
        ("io.linpodx.distro.instance".into(), params.name.clone()),
    ];

    CreateOptions {
        image: image_ref.to_string(),
        name: Some(container_name),
        command: Vec::new(),
        env: Vec::new(),
        labels,
        rm: false,
        detach: true,
        port_mappings: Vec::new(),
        volumes,
        networks: Vec::new(),
        cap_drop: Vec::new(),
        cap_add: Vec::new(),
        read_only: false,
        cpus: None,
        memory_mb: None,
        sandbox_profile: params.sandbox_profile.clone(),
        passthrough: Some(passthrough),
        systemd,
        auto_restart: params.vm_mode,
        keep_user_id: params.vm_mode,
        rootfs: None,
        security_opts: Vec::new(),
    }
}

/// Layer the user-supplied passthrough spec on top of the template default. Any flag
/// the user enables wins; flags the user explicitly disables (false) are also respected.
/// Conservatively, we OR the booleans so the caller's spec only ever adds privileges.
fn merge_passthrough(base: &PassthroughSpec, overlay: &Option<PassthroughSpec>) -> PassthroughSpec {
    let Some(o) = overlay else {
        return base.clone();
    };
    PassthroughSpec {
        wayland: base.wayland || o.wayland,
        x11: base.x11 || o.x11,
        audio: if matches!(o.audio, linpodx_common::passthrough::AudioMode::None) {
            base.audio
        } else {
            o.audio
        },
        gpu: base.gpu || o.gpu,
        dbus_session: base.dbus_session || o.dbus_session,
        clipboard: base.clipboard || o.clipboard,
        hidpi_inherit: base.hidpi_inherit || o.hidpi_inherit,
        register_app_menu: o
            .register_app_menu
            .clone()
            .or_else(|| base.register_app_menu.clone()),
    }
}

fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(DistroError::Runtime(format!(
            "invalid instance name '{name}': must be 1..=64 chars"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(DistroError::Runtime(format!(
            "invalid instance name '{name}': only [A-Za-z0-9_-] allowed"
        )));
    }
    Ok(())
}

async fn create_volume_if_missing(podman: &Podman, name: &str) -> Result<()> {
    let params = VolumeCreateParams {
        name: Some(name.to_string()),
        ..Default::default()
    };
    match rt_volume::create(podman, &params).await {
        Ok(_) => Ok(()),
        Err(CommonError::Runtime { message })
            if message.to_lowercase().contains("already exists") =>
        {
            Ok(())
        }
        Err(e) => Err(DistroError::Runtime(e.to_string())),
    }
}

async fn best_effort_remove_volume(podman: &Podman, name: &str) -> Result<()> {
    let params = VolumeRemoveParams {
        name: VolumeId(name.to_string()),
        force: true,
    };
    match rt_volume::remove(podman, &params).await {
        Ok(()) => Ok(()),
        Err(CommonError::NotFound(_)) => Ok(()),
        Err(e) => Err(DistroError::Runtime(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::NoopAuditSink;
    use linpodx_common::events::NoopEventPublisher;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("distro-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    fn manager(db: Arc<Database>) -> InstanceManager {
        InstanceManager::new(db, Arc::new(NoopEventPublisher), Arc::new(NoopAuditSink))
    }

    #[test]
    fn validate_name_accepts_simple_strings() {
        validate_instance_name("alpine-dev").unwrap();
        validate_instance_name("ubuntu_2404").unwrap();
        validate_instance_name("a").unwrap();
    }

    #[test]
    fn validate_name_rejects_bad_inputs() {
        assert!(validate_instance_name("").is_err());
        assert!(validate_instance_name("space here").is_err());
        assert!(validate_instance_name("slash/x").is_err());
        assert!(validate_instance_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn build_options_sets_systemd_for_ubuntu() {
        let template = Registry::inspect(DistroKind::Ubuntu);
        let params = DistroCreateParams {
            kind: DistroKind::Ubuntu,
            name: "u1".into(),
            vm_mode: false,
            passthrough: None,
            custom_image: None,
            sandbox_profile: None,
        };
        let opts = build_create_options(&template, &params, &template.default_image, None);
        assert!(opts.systemd);
        assert_eq!(opts.name.as_deref(), Some("linpodx-distro-u1"));
        assert!(!opts.auto_restart);
        assert!(!opts.keep_user_id);
        assert!(opts.volumes.is_empty());
    }

    #[test]
    fn build_options_in_vm_mode_mounts_home_and_keeps_uid() {
        let template = Registry::inspect(DistroKind::Alpine);
        let params = DistroCreateParams {
            kind: DistroKind::Alpine,
            name: "alp".into(),
            vm_mode: true,
            passthrough: None,
            custom_image: None,
            sandbox_profile: None,
        };
        let opts = build_create_options(
            &template,
            &params,
            &template.default_image,
            Some("linpodx-distro-alp-home"),
        );
        assert!(opts.auto_restart);
        assert!(opts.keep_user_id);
        assert!(!opts.systemd); // alpine = OpenRC
        assert_eq!(opts.volumes.len(), 1);
        assert_eq!(opts.volumes[0].source, "linpodx-distro-alp-home");
        assert_eq!(opts.volumes[0].destination, HOME_PATH_IN_CONTAINER);
    }

    #[test]
    fn merge_passthrough_or_logic() {
        let base = PassthroughSpec {
            wayland: true,
            ..Default::default()
        };
        let overlay = PassthroughSpec {
            gpu: true,
            ..Default::default()
        };
        let merged = merge_passthrough(&base, &Some(overlay));
        assert!(merged.wayland);
        assert!(merged.gpu);
    }

    #[test]
    fn merge_passthrough_no_overlay_returns_base() {
        let base = PassthroughSpec {
            wayland: true,
            ..Default::default()
        };
        let merged = merge_passthrough(&base, &None);
        assert!(merged.wayland);
    }

    #[tokio::test]
    async fn list_empty_returns_nothing() {
        let db = Arc::new(fresh_db().await);
        let mgr = manager(db);
        assert!(mgr.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn enter_unknown_returns_not_found() {
        let db = Arc::new(fresh_db().await);
        let mgr = manager(db);
        match mgr.enter("nope").await {
            Err(DistroError::NotFound(n)) => assert_eq!(n, "nope"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_returns_inserted_row() {
        let db = Arc::new(fresh_db().await);
        sqlx::query(
            "INSERT INTO distro_instances (name, kind, container_id, image_ref, vm_mode, \
             home_volume, auto_restart, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind("alp1")
        .bind("alpine")
        .bind("ctr-1")
        .bind("docker.io/library/alpine:latest")
        .bind(1_i64)
        .bind("linpodx-distro-alp1-home")
        .bind(1_i64)
        .bind("2026-05-09T00:00:00.000Z")
        .execute(db.pool())
        .await
        .unwrap();
        let mgr = manager(Arc::clone(&db));
        let list = mgr.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "alp1");
        assert_eq!(list[0].kind, DistroKind::Alpine);
        assert!(list[0].vm_mode);
    }

    #[tokio::test]
    async fn list_excludes_removed_rows() {
        let db = Arc::new(fresh_db().await);
        sqlx::query(
            "INSERT INTO distro_instances (name, kind, container_id, image_ref, removed_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("dead")
        .bind("ubuntu")
        .bind("c0")
        .bind("docker.io/library/ubuntu:24.04")
        .bind("2026-05-09T01:00:00.000Z")
        .bind("2026-05-09T00:00:00.000Z")
        .execute(db.pool())
        .await
        .unwrap();
        let mgr = manager(db);
        assert!(mgr.list().await.unwrap().is_empty());
    }
}
