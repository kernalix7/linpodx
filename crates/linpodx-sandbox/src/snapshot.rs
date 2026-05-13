//! Phase 2B snapshot manager.
//!
//! Wraps the runtime-level [`linpodx_runtime::snapshot`] helpers in business logic that
//! tracks each snapshot row in SQLite (`snapshots` table), records audit entries on the
//! tamper-evident chain, and publishes Snapshot-topic events.
//!
//! Image-ref naming: snapshots produced through this manager are tagged
//! `linpodx-snap-<seq>` (where `<seq>` is the SQLite-assigned `snapshots.id`). Rollback
//! creates a new container from a snapshot's image_ref.

use crate::audit::{self, AuditKind};
use chrono::Utc;
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{
    responses::{
        SnapshotBackendListResponse, SnapshotDiffResponse, SnapshotDiffV2Response,
        SnapshotRollbackResponse, SnapshotSummary,
    },
    CreateOptions, Event, EventKind, EventTopic,
};
use linpodx_common::passthrough::SnapshotBackendKind;
use linpodx_common::types::ContainerId;
use linpodx_runtime::{snapshot as runtime_snapshot, Podman, SnapshotBackend};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, instrument, warn};

const SNAPSHOT_REF_PREFIX: &str = "linpodx-snap";

pub struct SnapshotManager {
    db: Arc<Database>,
    publisher: Arc<dyn EventPublisher>,
    /// Phase 7: registered snapshot backends keyed by kind. The default constructor
    /// installs all three (PodmanCommit / Overlayfs / Btrfs); only PodmanCommit is
    /// fully implemented in v0.1, the others are scaffolds that return runtime errors
    /// from their mutating methods.
    backends: HashMap<SnapshotBackendKind, Arc<dyn SnapshotBackend>>,
}

impl SnapshotManager {
    pub fn new(db: Arc<Database>, publisher: Arc<dyn EventPublisher>) -> Self {
        let mut backends: HashMap<SnapshotBackendKind, Arc<dyn SnapshotBackend>> = HashMap::new();
        backends.insert(
            SnapshotBackendKind::PodmanCommit,
            Arc::new(runtime_snapshot::PodmanCommitBackend),
        );
        backends.insert(
            SnapshotBackendKind::Overlayfs,
            Arc::new(runtime_snapshot::OverlayfsBackend),
        );
        backends.insert(
            SnapshotBackendKind::Btrfs,
            Arc::new(runtime_snapshot::BtrfsBackend),
        );
        Self {
            db,
            publisher,
            backends,
        }
    }

    /// Test-only / explicit backend injection. Replaces the default registry — useful for
    /// unit tests that want to verify the manager dispatches to a specific backend.
    pub fn with_backends(
        db: Arc<Database>,
        publisher: Arc<dyn EventPublisher>,
        backends: HashMap<SnapshotBackendKind, Arc<dyn SnapshotBackend>>,
    ) -> Self {
        Self {
            db,
            publisher,
            backends,
        }
    }

    /// Read the backend kind recorded on a `snapshots` row. Returns `None` if the row
    /// doesn't exist or the value can't be parsed (caller falls back to default).
    async fn row_backend(&self, id: i64) -> Option<SnapshotBackendKind> {
        let raw: Option<String> = sqlx::query_scalar("SELECT backend FROM snapshots WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await
            .ok()
            .flatten();
        raw.and_then(|s| SnapshotBackendKind::parse(&s).ok())
    }

    /// Look up a backend by kind, falling back to PodmanCommit if the requested kind is
    /// not registered (should not happen with the default constructor).
    fn backend(&self, kind: SnapshotBackendKind) -> Arc<dyn SnapshotBackend> {
        self.backends
            .get(&kind)
            .cloned()
            .unwrap_or_else(|| Arc::new(runtime_snapshot::PodmanCommitBackend))
    }

    /// Reports each registered backend's availability + note. Order is not guaranteed
    /// (HashMap iteration); the daemon dispatch arm sorts canonically before returning
    /// to the client.
    pub async fn backend_list(&self) -> SnapshotBackendListResponse {
        runtime_snapshot::backend_list().await
    }

    /// Layer-aware diff between two snapshot rows. Looks both `image_ref`s up in the DB
    /// then delegates to `runtime_snapshot::diff_v2`. The response's `id_a` / `id_b`
    /// fields are filled with the snapshot row ids (the runtime layer leaves them at 0).
    #[instrument(skip(self, podman))]
    pub async fn diff_v2(
        &self,
        podman: &Podman,
        id_a: i64,
        id_b: i64,
    ) -> Result<SnapshotDiffV2Response> {
        let a = self.inspect(id_a).await?;
        let b = self.inspect(id_b).await?;
        let mut resp = runtime_snapshot::diff_v2(podman, &a.image_ref, &b.image_ref).await?;
        resp.id_a = id_a;
        resp.id_b = id_b;
        Ok(resp)
    }

    /// Append a `SnapshotBackendUsed` audit entry recording which backend was selected
    /// for a given snapshot id. Best-effort — failures are logged but do not bubble up.
    async fn audit_backend_used(
        &self,
        kind: SnapshotBackendKind,
        snapshot_id: i64,
        container_id: &str,
    ) {
        if let Err(e) = audit::append(
            &self.db,
            AuditKind::SnapshotBackendUsed,
            None,
            Some(container_id.to_string()),
            serde_json::json!({
                "kind": kind.as_str(),
                "snapshot_id": snapshot_id,
            }),
        )
        .await
        {
            warn!(error = %e, snapshot_id, "snapshot_backend_used audit append failed");
        }
    }

    /// Read-only access to the shared `Database` so sibling subsystems (notably
    /// `linpodx-distro`'s `InstanceManager`) can reuse the same SQLite handle without
    /// having to thread a separate `Arc<Database>` through `Dispatcher`.
    pub fn database(&self) -> &Arc<Database> {
        &self.db
    }

    /// Borrow the event publisher so async snapshot jobs scheduled through the
    /// runtime layer (Phase 2E) can route their progress events to the same bus.
    pub fn publisher(&self) -> Arc<dyn EventPublisher> {
        Arc::clone(&self.publisher)
    }

    /// Snapshot a running container into an OCI image and record the row.
    /// `parent_id` is set to the most-recent snapshot (if any) for the same container so the
    /// UI can render lineage. Defaults to the PodmanCommit backend; callers wanting an
    /// alternate backend (typically resolved from the active SandboxProfile) should use
    /// [`Self::create_with_backend`].
    #[instrument(skip(self, podman), fields(container_id = %container_id.0))]
    pub async fn create(
        &self,
        podman: &Podman,
        container_id: &ContainerId,
        label: Option<String>,
    ) -> Result<SnapshotSummary> {
        self.create_with_backend(podman, container_id, label, None)
            .await
    }

    /// Same as [`Self::create`] but with explicit backend selection. `None` defaults to
    /// `PodmanCommit`. Records the resolved backend on the snapshot row (`backend`
    /// column) and appends a `SnapshotBackendUsed` audit entry.
    #[instrument(skip(self, podman), fields(container_id = %container_id.0))]
    pub async fn create_with_backend(
        &self,
        podman: &Podman,
        container_id: &ContainerId,
        label: Option<String>,
        backend_kind: Option<SnapshotBackendKind>,
    ) -> Result<SnapshotSummary> {
        let kind = backend_kind.unwrap_or_default();
        let backend = self.backend(kind);

        let parent_id: Option<i64> = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM snapshots WHERE container_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(&container_id.0)
        .fetch_optional(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;

        // Pre-allocate the row so we can shape `image_ref` from the assigned id.
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let placeholder_ref = format!("{SNAPSHOT_REF_PREFIX}-pending");
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at, backend) \
             VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&container_id.0)
        .bind(&label)
        .bind(&placeholder_ref)
        .bind(parent_id)
        .bind(&now_str)
        .bind(kind.as_str())
        .fetch_one(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        let id = row.0;
        let image_ref = format!("{SNAPSHOT_REF_PREFIX}-{id}");

        let commit_outcome = backend.commit(podman, container_id, &image_ref).await;
        if let Err(e) = &commit_outcome {
            warn!(error = %e, snapshot_id = id, backend = %kind, "snapshot commit failed; rolling back row");
            // Best-effort cleanup so we don't leak orphan rows.
            let _ = sqlx::query("DELETE FROM snapshots WHERE id = ?")
                .bind(id)
                .execute(self.db.pool())
                .await;
        }
        let _committed_image = commit_outcome?;

        // Promote placeholder to the final image_ref.
        sqlx::query("UPDATE snapshots SET image_ref = ? WHERE id = ?")
            .bind(&image_ref)
            .bind(id)
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;

        // Best-effort size lookup; failure is non-fatal — metadata only.
        let size_bytes = match runtime_snapshot::inspect(podman, &image_ref).await {
            Ok(insp) => Some(insp.size_bytes),
            Err(e) => {
                warn!(error = %e, "snapshot inspect for size lookup failed");
                None
            }
        };
        if let Some(sz) = size_bytes {
            let _ = sqlx::query("UPDATE snapshots SET size_bytes = ? WHERE id = ?")
                .bind(sz as i64)
                .bind(id)
                .execute(self.db.pool())
                .await;
        }

        self.audit_backend_used(kind, id, &container_id.0).await;

        let summary = SnapshotSummary {
            id,
            container_id: container_id.0.clone(),
            label: label.clone(),
            image_ref: image_ref.clone(),
            parent_id,
            created_at: now,
            size_bytes,
        };

        audit::append(
            &self.db,
            AuditKind::SnapshotCreated,
            None,
            Some(container_id.0.clone()),
            serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Snapshot,
            kind: EventKind::Created,
            resource_id: image_ref,
            timestamp: Utc::now(),
            details: serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        });
        info!(snapshot_id = id, container = %container_id.0, "snapshot created");
        Ok(summary)
    }

    #[instrument(skip(self))]
    pub async fn list(&self, container_id: Option<&str>) -> Result<Vec<SnapshotSummary>> {
        let rows: Vec<SnapRow> = match container_id {
            Some(cid) => sqlx::query_as::<_, SnapRow>(
                "SELECT id, container_id, label, image_ref, parent_id, created_at, size_bytes \
                 FROM snapshots WHERE container_id = ? ORDER BY id DESC",
            )
            .bind(cid)
            .fetch_all(self.db.pool())
            .await
            .map_err(Error::Sqlx)?,
            None => sqlx::query_as::<_, SnapRow>(
                "SELECT id, container_id, label, image_ref, parent_id, created_at, size_bytes \
                 FROM snapshots ORDER BY id DESC",
            )
            .fetch_all(self.db.pool())
            .await
            .map_err(Error::Sqlx)?,
        };
        rows.into_iter().map(SnapRow::into_summary).collect()
    }

    #[instrument(skip(self))]
    pub async fn inspect(&self, id: i64) -> Result<SnapshotSummary> {
        let row = sqlx::query_as::<_, SnapRow>(
            "SELECT id, container_id, label, image_ref, parent_id, created_at, size_bytes \
             FROM snapshots WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(Error::Sqlx)?
        .ok_or_else(|| Error::NotFound(format!("snapshot {id}")))?;
        row.into_summary()
    }

    #[instrument(skip(self, podman))]
    pub async fn remove(&self, podman: &Podman, id: i64, force: bool) -> Result<()> {
        let summary = self.inspect(id).await?;
        let kind = self.row_backend(id).await.unwrap_or_default();
        let backend = self.backend(kind);
        match backend.remove(podman, &summary.image_ref, force).await {
            Ok(()) => {}
            Err(Error::NotFound(_)) => {
                warn!(snapshot_id = id, image_ref = %summary.image_ref, "image gone before remove; clearing row anyway");
            }
            // Scaffold backends (Overlayfs/Btrfs) return Runtime — fall back to PodmanCommit
            // so we can still clean up images that were taken with the default backend
            // before someone retroactively edited the row's `backend` column.
            Err(Error::Runtime { message }) => {
                warn!(snapshot_id = id, backend = %kind, %message, "backend remove not implemented; falling back to podman_commit");
                if let Err(e) = runtime_snapshot::remove(podman, &summary.image_ref, force).await {
                    if !matches!(e, Error::NotFound(_)) {
                        return Err(e);
                    }
                }
            }
            Err(e) => return Err(e),
        }
        sqlx::query("DELETE FROM snapshots WHERE id = ?")
            .bind(id)
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;
        audit::append(
            &self.db,
            AuditKind::SnapshotRemoved,
            None,
            Some(summary.container_id.clone()),
            serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Snapshot,
            kind: EventKind::Removed,
            resource_id: summary.image_ref.clone(),
            timestamp: Utc::now(),
            details: serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        });
        Ok(())
    }

    /// Prune snapshots, keeping the `keep_recent` newest per scope.
    #[instrument(skip(self, podman))]
    pub async fn prune(
        &self,
        podman: &Podman,
        container_id: Option<&str>,
        keep_recent: u32,
    ) -> Result<Vec<i64>> {
        let candidates = self.list(container_id).await?;
        let to_remove: Vec<i64> = candidates
            .into_iter()
            .skip(keep_recent as usize)
            .map(|s| s.id)
            .collect();
        let mut removed = Vec::with_capacity(to_remove.len());
        for id in to_remove {
            match self.remove(podman, id, false).await {
                Ok(()) => removed.push(id),
                Err(e) => {
                    warn!(error = %e, snapshot_id = id, "prune: skip on remove error");
                }
            }
        }
        Ok(removed)
    }

    /// Rebuild a container from a snapshot. Spawns a new container from `image_ref`,
    /// optionally removing the original container.
    #[instrument(skip(self, podman))]
    pub async fn rollback(
        &self,
        podman: &Podman,
        id: i64,
        new_name: Option<String>,
        keep_original: bool,
    ) -> Result<SnapshotRollbackResponse> {
        let summary = self.inspect(id).await?;
        let original_id = ContainerId::new(summary.container_id.clone());

        // Best-effort original-container inspection so we can preserve the most useful
        // fields. If inspection fails (container removed) we proceed with bare CreateOptions.
        let opts = match podman.inspect(&original_id).await {
            Ok(insp) => CreateOptions {
                image: summary.image_ref.clone(),
                name: new_name.clone(),
                command: insp.command.clone(),
                env: insp.env.into_iter().collect(),
                labels: insp.labels.into_iter().collect(),
                detach: true,
                ..Default::default()
            },
            Err(e) => {
                warn!(error = %e, "could not inspect original container; rolling back with minimal opts");
                CreateOptions {
                    image: summary.image_ref.clone(),
                    name: new_name.clone(),
                    detach: true,
                    ..Default::default()
                }
            }
        };

        let new_id = podman.create(&opts).await?;

        if !keep_original {
            if let Err(e) = podman.remove(&original_id, true).await {
                warn!(error = %e, original = %original_id.0, "failed removing original container during rollback");
            }
        }

        let resolved_name = opts
            .name
            .clone()
            .unwrap_or_else(|| format!("{}-restored", summary.container_id));
        let response = SnapshotRollbackResponse {
            new_container_id: new_id.0.clone(),
            new_container_name: resolved_name,
        };
        audit::append(
            &self.db,
            AuditKind::SnapshotRolledBack,
            None,
            Some(summary.container_id.clone()),
            serde_json::json!({
                "snapshot_id": id,
                "image_ref": summary.image_ref,
                "new_container_id": response.new_container_id,
                "new_container_name": response.new_container_name,
                "keep_original": keep_original,
            }),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Snapshot,
            kind: EventKind::Started,
            resource_id: response.new_container_id.clone(),
            timestamp: Utc::now(),
            details: serde_json::json!({
                "snapshot_id": id,
                "image_ref": summary.image_ref,
                "new_container_name": response.new_container_name,
            }),
        });
        Ok(response)
    }

    /// Branch a snapshot. Two modes:
    ///
    /// * `fork = false` (default): tag the parent's image with a fresh
    ///   `*-branch-<sha8>` ref via `podman tag` and insert a new `snapshots` row pointing
    ///   at the same content. The two rows refer to identical image content; removing
    ///   one tag leaves the other intact.
    /// * `fork = true`: run a real `podman commit` from the parent's `container_id` so
    ///   the new row owns its own image content (fork-on-write). The parent's container
    ///   must still exist; if podman cannot find it, an [`Error::NotFound`] is returned.
    ///   `size_bytes` is re-inspected after the commit since the new image may diverge
    ///   in size from the parent's snapshot.
    #[instrument(skip(self, podman))]
    pub async fn create_branch(
        &self,
        podman: &Podman,
        parent_id: i64,
        label: Option<String>,
        fork: bool,
    ) -> Result<SnapshotSummary> {
        let parent = self.inspect(parent_id).await?;
        let new_ref = branch_image_ref(&parent.image_ref, parent_id);
        // Inherit the parent row's backend so a forked branch stays on the same engine.
        let kind = self.row_backend(parent_id).await.unwrap_or_default();
        let backend = self.backend(kind);

        let mut size_bytes = parent.size_bytes;
        if fork {
            let parent_cid = ContainerId::new(parent.container_id.clone());
            backend.commit(podman, &parent_cid, &new_ref).await?;
            // Re-inspect so the new row records the post-commit size; failure here is
            // metadata-only, so we keep the parent's size as a best-effort fallback.
            match runtime_snapshot::inspect(podman, &new_ref).await {
                Ok(insp) => size_bytes = Some(insp.size_bytes),
                Err(e) => warn!(error = %e, "fork branch inspect for size lookup failed"),
            }
        } else {
            backend.tag(podman, &parent.image_ref, &new_ref).await?;
        }

        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at, size_bytes, backend) \
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(&parent.container_id)
        .bind(&label)
        .bind(&new_ref)
        .bind(parent_id)
        .bind(&now_str)
        .bind(size_bytes.map(|n| n as i64))
        .bind(kind.as_str())
        .fetch_one(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        let new_id = row.0;
        self.audit_backend_used(kind, new_id, &parent.container_id)
            .await;

        let summary = SnapshotSummary {
            id: new_id,
            container_id: parent.container_id.clone(),
            label: label.clone(),
            image_ref: new_ref.clone(),
            parent_id: Some(parent_id),
            created_at: now,
            size_bytes,
        };

        audit::append(
            &self.db,
            AuditKind::SnapshotBranched,
            None,
            Some(parent.container_id.clone()),
            serde_json::json!({
                "parent_id": parent_id,
                "new_id": new_id,
                "image_ref": new_ref,
                "label": label,
                "fork": fork,
            }),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Snapshot,
            kind: EventKind::Created,
            resource_id: new_ref.clone(),
            timestamp: Utc::now(),
            details: serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        });
        info!(snapshot_id = new_id, parent_id, "snapshot branch created");
        Ok(summary)
    }

    /// Compute a content diff between two snapshots' image refs. Returns added /
    /// modified / deleted path lists plus the byte delta between the two images.
    #[instrument(skip(self, podman))]
    pub async fn diff(
        &self,
        podman: &Podman,
        id_a: i64,
        id_b: i64,
    ) -> Result<SnapshotDiffResponse> {
        let a = self.inspect(id_a).await?;
        let b = self.inspect(id_b).await?;
        let raw = runtime_snapshot::diff(podman, &a.image_ref, &b.image_ref).await?;
        let size_a = match runtime_snapshot::image_size_bytes(podman, &a.image_ref).await {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, image_ref = %a.image_ref, "size lookup for A failed; treating as 0");
                0
            }
        };
        let size_b = match runtime_snapshot::image_size_bytes(podman, &b.image_ref).await {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, image_ref = %b.image_ref, "size lookup for B failed; treating as 0");
                0
            }
        };
        Ok(SnapshotDiffResponse {
            id_a,
            id_b,
            added: raw.added,
            modified: raw.modified,
            deleted: raw.deleted,
            size_delta_bytes: size_b - size_a,
        })
    }
}

/// Deterministic branch image ref: `<parent>-branch-<sha8(now+parent_id)>`.
fn branch_image_ref(parent_ref: &str, parent_id: i64) -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(nanos.to_le_bytes());
    h.update(parent_id.to_le_bytes());
    let digest = h.finalize();
    let mut sha8 = String::with_capacity(8);
    for b in digest.iter().take(4) {
        sha8.push_str(&format!("{b:02x}"));
    }
    format!("{parent_ref}-branch-{sha8}")
}

#[derive(sqlx::FromRow)]
struct SnapRow {
    id: i64,
    container_id: String,
    label: Option<String>,
    image_ref: String,
    parent_id: Option<i64>,
    created_at: String,
    size_bytes: Option<i64>,
}

impl SnapRow {
    fn into_summary(self) -> Result<SnapshotSummary> {
        let created_at = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .map_err(|e| Error::Runtime {
                message: format!("invalid snapshot created_at '{}': {e}", self.created_at),
            })?;
        Ok(SnapshotSummary {
            id: self.id,
            container_id: self.container_id,
            label: self.label,
            image_ref: self.image_ref,
            parent_id: self.parent_id,
            created_at,
            size_bytes: self.size_bytes.map(|n| n as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::events::NoopEventPublisher;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("snap-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn list_empty_returns_nothing() {
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        assert!(mgr.list(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_filters_by_container() {
        let db = Arc::new(fresh_db().await);
        // Hand-insert two rows since we can't call podman in unit tests.
        sqlx::query(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at) \
             VALUES (?, ?, ?, NULL, ?)",
        )
        .bind("c1")
        .bind("first")
        .bind("linpodx-snap-1")
        .bind("2026-05-09T00:00:00.000Z")
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at) \
             VALUES (?, ?, ?, NULL, ?)",
        )
        .bind("c2")
        .bind("other")
        .bind("linpodx-snap-2")
        .bind("2026-05-09T00:00:01.000Z")
        .execute(db.pool())
        .await
        .unwrap();

        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let all = mgr.list(None).await.unwrap();
        assert_eq!(all.len(), 2);
        let only_c1 = mgr.list(Some("c1")).await.unwrap();
        assert_eq!(only_c1.len(), 1);
        assert_eq!(only_c1[0].container_id, "c1");
    }

    #[tokio::test]
    async fn inspect_missing_returns_not_found() {
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        match mgr.inspect(999).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn branch_image_ref_pattern_is_stable_prefix() {
        let r = branch_image_ref("linpodx-snap-7", 7);
        assert!(r.starts_with("linpodx-snap-7-branch-"));
        // sha8 segment is exactly 8 hex chars.
        let suffix = r.trim_start_matches("linpodx-snap-7-branch-");
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn create_branch_inserts_child_row_and_audits() {
        use linpodx_runtime::podman::PodmanConfig;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let scratch = tempfile::tempdir().expect("scratch");
        // Fake podman that succeeds for `tag` (alias). The write handle must be dropped
        // before exec — Linux returns ETXTBSY if a file is opened for writing while we
        // try to spawn it.
        let bin = scratch.path().join("podman-fake");
        {
            let mut f = std::fs::File::create(&bin).unwrap();
            writeln!(f, "#!/bin/sh\nexit 0\n").unwrap();
        }
        let mut perm = std::fs::metadata(&bin).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&bin, perm).unwrap();

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin),
            ..Default::default()
        });

        let db = Arc::new(fresh_db().await);
        sqlx::query(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at, size_bytes) \
             VALUES (?, ?, ?, NULL, ?, ?)",
        )
        .bind("c-parent")
        .bind("base")
        .bind("linpodx-snap-1")
        .bind("2026-05-09T00:00:00.000Z")
        .bind(1024_i64)
        .execute(db.pool())
        .await
        .unwrap();

        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let summary = mgr
            .create_branch(&podman, 1, Some("dev".into()), false)
            .await
            .expect("create_branch");

        assert_eq!(summary.parent_id, Some(1));
        assert_eq!(summary.container_id, "c-parent");
        assert!(summary.image_ref.starts_with("linpodx-snap-1-branch-"));
        assert_eq!(summary.label.as_deref(), Some("dev"));

        // DB row exists with the right parent linkage.
        let row: (i64, Option<i64>, String) =
            sqlx::query_as("SELECT id, parent_id, image_ref FROM snapshots WHERE id = ?")
                .bind(summary.id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(row.0, summary.id);
        assert_eq!(row.1, Some(1));
        assert!(row.2.starts_with("linpodx-snap-1-branch-"));

        // Audit row was appended with the branched kind.
        let audit_kind: (String,) =
            sqlx::query_as("SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(audit_kind.0, "snapshot_branched");
    }

    #[tokio::test]
    async fn create_branch_missing_parent_returns_not_found() {
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let podman = Podman::default();
        match mgr.create_branch(&podman, 999, None, false).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_branch_fork_invokes_commit_path() {
        // Drives the fork=true branch: a fake podman that always exits 0 covers both
        // `commit` (alias path is bypassed) and the follow-up `inspect` (which fails
        // to parse JSON — non-fatal). The DB row should still land with parent linkage
        // and a `fork=true` audit payload.
        use linpodx_runtime::podman::PodmanConfig;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let scratch = tempfile::tempdir().expect("scratch");
        let bin = scratch.path().join("podman-fake");
        {
            let mut f = std::fs::File::create(&bin).unwrap();
            // `podman commit` prints a single image id on stdout; size lookup will fail
            // to parse JSON but that's swallowed as a metadata-only warning.
            writeln!(f, "#!/bin/sh\necho deadbeef\nexit 0\n").unwrap();
        }
        let mut perm = std::fs::metadata(&bin).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&bin, perm).unwrap();

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin),
            ..Default::default()
        });

        let db = Arc::new(fresh_db().await);
        sqlx::query(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at, size_bytes) \
             VALUES (?, ?, ?, NULL, ?, ?)",
        )
        .bind("c-live")
        .bind(Option::<String>::None)
        .bind("linpodx-snap-1")
        .bind("2026-05-09T00:00:00.000Z")
        .bind(2048_i64)
        .execute(db.pool())
        .await
        .unwrap();

        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let summary = mgr
            .create_branch(&podman, 1, Some("forked".into()), true)
            .await
            .expect("create_branch fork=true");

        assert_eq!(summary.parent_id, Some(1));
        assert_eq!(summary.container_id, "c-live");
        assert_eq!(summary.label.as_deref(), Some("forked"));
        assert!(summary.image_ref.starts_with("linpodx-snap-1-branch-"));

        let audit_row: (String, String) =
            sqlx::query_as("SELECT kind, payload FROM audit_log ORDER BY seq DESC LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(audit_row.0, "snapshot_branched");
        let payload: serde_json::Value = serde_json::from_str(&audit_row.1).unwrap();
        assert_eq!(payload.get("fork").and_then(|v| v.as_bool()), Some(true));
    }

    // ----- Phase 7 backend dispatch tests -----

    #[tokio::test]
    async fn backend_list_includes_three_backends() {
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let list = mgr.backend_list().await;
        assert_eq!(list.len(), 3);
        let kinds: Vec<_> = list.iter().map(|b| b.kind).collect();
        assert!(kinds.contains(&SnapshotBackendKind::PodmanCommit));
        assert!(kinds.contains(&SnapshotBackendKind::Overlayfs));
        assert!(kinds.contains(&SnapshotBackendKind::Btrfs));
    }

    #[tokio::test]
    async fn row_backend_returns_default_for_missing_row() {
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        // No row → None → unwrap_or_default → PodmanCommit.
        assert_eq!(mgr.row_backend(999).await, None);
    }

    #[tokio::test]
    async fn row_backend_parses_recorded_kind() {
        let db = Arc::new(fresh_db().await);
        sqlx::query(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at, backend) \
             VALUES (?, ?, ?, NULL, ?, ?)",
        )
        .bind("c-bkd")
        .bind(Option::<String>::None)
        .bind("linpodx-snap-1")
        .bind("2026-05-10T00:00:00.000Z")
        .bind("overlayfs")
        .execute(db.pool())
        .await
        .unwrap();
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        assert_eq!(
            mgr.row_backend(1).await,
            Some(SnapshotBackendKind::Overlayfs)
        );
    }

    #[tokio::test]
    async fn create_with_overlayfs_backend_rolls_back_on_failure() {
        // Phase 8 — OverlayfsBackend.commit() now actually runs `podman cp`. With a
        // non-existent podman binary the spawn fails, so create_with_backend(Overlayfs)
        // must surface *some* error AND roll the row back. Either Io (spawn missing
        // binary) or Runtime (older `looks_like_not_found` path) is acceptable — the
        // contract being checked is "row count returns to 0", not the specific kind.
        use linpodx_runtime::podman::PodmanConfig;
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(std::path::PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let cid = ContainerId::new("c-overlayfs".to_string());
        let res = mgr
            .create_with_backend(&podman, &cid, None, Some(SnapshotBackendKind::Overlayfs))
            .await;
        assert!(
            res.is_err(),
            "create_with_backend(Overlayfs) with missing podman should fail; got {res:?}"
        );
        // Row was rolled back.
        let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE container_id = ?")
            .bind(&cid.0)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(cnt.0, 0);
    }

    #[tokio::test]
    async fn diff_v2_inspect_missing_returns_not_found() {
        let db = Arc::new(fresh_db().await);
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let podman = Podman::default();
        match mgr.diff_v2(&podman, 1, 2).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound for missing snapshot ids, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inspect_returns_row_when_present() {
        let db = Arc::new(fresh_db().await);
        sqlx::query(
            "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at, size_bytes) \
             VALUES (?, ?, ?, NULL, ?, ?)",
        )
        .bind("cabc")
        .bind(Option::<String>::None)
        .bind("linpodx-snap-1")
        .bind("2026-05-09T00:00:00.000Z")
        .bind(12345_i64)
        .execute(db.pool())
        .await
        .unwrap();
        let mgr = SnapshotManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let s = mgr.inspect(1).await.unwrap();
        assert_eq!(s.container_id, "cabc");
        assert_eq!(s.size_bytes, Some(12345));
        assert_eq!(s.image_ref, "linpodx-snap-1");
    }
}
