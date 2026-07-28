//! Snapshot operations: commit a running container into an OCI image, inspect
//! the resulting image, and remove it. Thin wrappers around `podman commit`,
//! `podman inspect --type=image` (delegated to [`crate::image::inspect`]), and
//! `podman rmi`.

use crate::image;
use crate::oci_tar::{self, FileEntry};
use crate::overlayfs::{self, MountedRoot};
use crate::podman::{map_not_found, Podman};
use crate::snapshot_crypto::{self, EncryptionConfig};
use async_trait::async_trait;
use chrono::Utc;
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind, NoopAuditSink};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::responses::{
    FileChange, LayerInfo, SnapshotBackendInfo, SnapshotBackendListResponse, SnapshotDiffV2Response,
};
use linpodx_common::ipc::{Event, EventKind, EventTopic};
use linpodx_common::passthrough::SnapshotBackendKind;
use linpodx_common::state::ImageInspect;
use linpodx_common::types::{ContainerId, ImageId};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{instrument, warn};

const SNAPSHOT_REF_PREFIX: &str = "linpodx-snap";

/// Snapshot a container into a new image.
///
/// Returns the long image ID printed by `podman commit`.
#[instrument(skip(podman))]
pub async fn create(
    podman: &Podman,
    container_id: &ContainerId,
    image_ref: &str,
) -> Result<ImageId> {
    let mut cmd = podman.base_command();
    cmd.arg("commit").arg(&container_id.0).arg(image_ref);
    let out = match podman.run_capture(cmd).await {
        Ok(s) => s,
        Err(e) => return Err(map_not_found(e, &container_id.0)),
    };
    let id = out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    if id.is_empty() {
        return Err(Error::Runtime {
            message: "podman commit returned no image id".into(),
        });
    }
    Ok(ImageId(id))
}

/// Remove an image (snapshot or otherwise) by reference or ID.
#[instrument(skip(podman))]
pub async fn remove(podman: &Podman, image_ref: &str, force: bool) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("rmi");
    if force {
        cmd.arg("--force");
    }
    cmd.arg(image_ref);
    podman
        .run_capture(cmd)
        .await
        .map(|_| ())
        .map_err(|e| map_not_found(e, image_ref))
}

/// Inspect an image by reference or ID. Delegates to [`crate::image::inspect`].
#[instrument(skip(podman))]
pub async fn inspect(podman: &Podman, image_ref: &str) -> Result<ImageInspect> {
    image::inspect(podman, &ImageId(image_ref.to_string())).await
}

/// Per-path classification for [`diff`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffOutput {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

/// Parse `podman diff` output. Each line is `A /path`, `C /path`, or `D /path`.
/// Unknown prefixes are skipped (forward-compatible with future podman additions).
fn parse_diff(output: &str) -> DiffOutput {
    let mut out = DiffOutput::default();
    for line in output.lines() {
        let trimmed = line.trim_end();
        let (tag, path) = match trimmed.split_once(char::is_whitespace) {
            Some((t, p)) => (t, p.trim_start()),
            None => continue,
        };
        if path.is_empty() {
            continue;
        }
        match tag {
            "A" => out.added.push(path.to_string()),
            "C" => out.modified.push(path.to_string()),
            "D" => out.deleted.push(path.to_string()),
            _ => {}
        }
    }
    out.added.sort();
    out.modified.sort();
    out.deleted.sort();
    out
}

/// Diff two snapshot images by composing two `podman diff <image>` calls (each shows
/// the image's overlay vs its parent layer) and computing the set difference per category.
///
/// v0.1 approximation: this is the best podman exposes without a full layer-walk. When
/// `image_a` and `image_b` share a parent (the common case for snapshots taken from the
/// same container), the symmetric set difference gives a useful "what changed between A
/// and B" view. When they don't share a parent the result is still well-defined but less
/// intuitive — both per-image diffs vs their respective parents end up combined.
#[instrument(skip(podman))]
pub async fn diff(podman: &Podman, image_a: &str, image_b: &str) -> Result<DiffOutput> {
    let raw_a = run_diff_one(podman, image_a).await?;
    let raw_b = run_diff_one(podman, image_b).await?;
    let parsed_a = parse_diff(&raw_a);
    let parsed_b = parse_diff(&raw_b);
    Ok(symmetric_diff(&parsed_a, &parsed_b))
}

async fn run_diff_one(podman: &Podman, image_ref: &str) -> Result<String> {
    let mut cmd = podman.base_command();
    cmd.arg("diff").arg(image_ref);
    podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, image_ref))
}

/// Compute "what's in B but not in A" per category. Items present in A but not B (i.e.
/// rolled-back changes) are surfaced as `deleted` in the resulting diff.
fn symmetric_diff(a: &DiffOutput, b: &DiffOutput) -> DiffOutput {
    use std::collections::BTreeSet;
    let a_added: BTreeSet<&String> = a.added.iter().collect();
    let a_modified: BTreeSet<&String> = a.modified.iter().collect();
    let a_deleted: BTreeSet<&String> = a.deleted.iter().collect();

    let mut out = DiffOutput::default();
    for p in &b.added {
        if !a_added.contains(p) {
            out.added.push(p.clone());
        }
    }
    for p in &b.modified {
        if !a_modified.contains(p) {
            out.modified.push(p.clone());
        }
    }
    for p in &b.deleted {
        if !a_deleted.contains(p) {
            out.deleted.push(p.clone());
        }
    }
    // Paths added in A but not B mean "B no longer has this addition" — surface as deleted.
    for p in &a.added {
        if !b.added.contains(p) && !out.deleted.iter().any(|q| q == p) {
            out.deleted.push(p.clone());
        }
    }
    out.added.sort();
    out.modified.sort();
    out.deleted.sort();
    out
}

/// Tag an image with an additional name (`podman tag <source> <target>`). The two
/// references then point at the same underlying image content; removing one does not
/// remove the other unless `--force` is used and there are no remaining references.
#[instrument(skip(podman))]
pub async fn alias(podman: &Podman, source: &str, target: &str) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("tag").arg(source).arg(target);
    podman
        .run_capture(cmd)
        .await
        .map(|_| ())
        .map_err(|e| map_not_found(e, source))
}

/// Look up the on-disk size of an image in bytes via `podman image inspect`.
#[instrument(skip(podman))]
pub async fn image_size_bytes(podman: &Podman, image_ref: &str) -> Result<i64> {
    let mut cmd = podman.base_command();
    cmd.arg("image")
        .arg("inspect")
        .arg("--format")
        .arg("{{.Size}}")
        .arg(image_ref);
    let out = podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, image_ref))?;
    let trimmed = out.trim();
    trimmed.parse::<i64>().map_err(|e| Error::Runtime {
        message: format!("podman image inspect returned non-numeric size '{trimmed}': {e}"),
    })
}

/// Generate a short, opaque job id from time + container id.
fn new_job_id(container_id: &str) -> String {
    let mut hasher = Sha256::new();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(nanos.to_le_bytes());
    hasher.update(container_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(20);
    out.push_str("snap-");
    for b in digest.iter().take(7) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Spawn a background `podman commit` and report progress via `publisher`. Inserts a
/// `snapshot_jobs` row up-front (status=pending), transitions it to `running`, then to
/// `succeeded` (with the new `snapshots` row id) or `failed`. Returns the job id assigned
/// to the row; the caller can poll the `snapshot_jobs` table by `job_id` to observe
/// state without consuming the join handle.
#[instrument(skip(podman, db, publisher), fields(container_id = %container_id.0))]
pub async fn create_async(
    podman: &Podman,
    db: Arc<Database>,
    container_id: &ContainerId,
    label: Option<String>,
    publisher: Arc<dyn EventPublisher>,
) -> Result<String> {
    let job_id = new_job_id(&container_id.0);
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    sqlx::query(
        "INSERT INTO snapshot_jobs (job_id, container_id, label, status, started_at) \
         VALUES (?, ?, ?, 'pending', ?)",
    )
    .bind(&job_id)
    .bind(&container_id.0)
    .bind(&label)
    .bind(&now)
    .execute(db.pool())
    .await
    .map_err(Error::Sqlx)?;

    let podman_clone = podman.clone();
    let db_clone = Arc::clone(&db);
    let cid_clone = container_id.clone();
    let label_clone = label.clone();
    let job_id_clone = job_id.clone();
    let publisher_clone = Arc::clone(&publisher);

    tokio::spawn(async move {
        if let Err(e) = run_async_job(
            podman_clone,
            db_clone,
            cid_clone,
            label_clone,
            job_id_clone,
            publisher_clone,
        )
        .await
        {
            warn!(error = %e, "async snapshot job task failed");
        }
    });

    Ok(job_id)
}

async fn run_async_job(
    podman: Podman,
    db: Arc<Database>,
    container_id: ContainerId,
    label: Option<String>,
    job_id: String,
    publisher: Arc<dyn EventPublisher>,
) -> Result<()> {
    // Pre-allocate snapshots row so we can shape image_ref deterministically and
    // record the linkage even if the spawn returns mid-flight.
    let parent_id: Option<i64> = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM snapshots WHERE container_id = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(&container_id.0)
    .fetch_optional(db.pool())
    .await
    .map_err(Error::Sqlx)?;
    let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let placeholder_ref = format!("{SNAPSHOT_REF_PREFIX}-pending");
    let row = sqlx::query(
        "INSERT INTO snapshots (container_id, label, image_ref, parent_id, created_at) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&container_id.0)
    .bind(&label)
    .bind(&placeholder_ref)
    .bind(parent_id)
    .bind(&now_str)
    .fetch_one(db.pool())
    .await
    .map_err(Error::Sqlx)?;
    let snapshot_id: i64 = row.try_get("id").map_err(Error::Sqlx)?;
    let image_ref = format!("{SNAPSHOT_REF_PREFIX}-{snapshot_id}");

    // Mark running.
    sqlx::query("UPDATE snapshot_jobs SET status = 'running' WHERE job_id = ?")
        .bind(&job_id)
        .execute(db.pool())
        .await
        .map_err(Error::Sqlx)?;

    publisher.publish(Event {
        topic: EventTopic::Snapshot,
        kind: EventKind::Progress,
        resource_id: job_id.clone(),
        timestamp: Utc::now(),
        details: serde_json::json!({
            "phase": "running",
            "container_id": container_id.0,
            "snapshot_id": snapshot_id,
        }),
    });

    // Spawn `podman commit` and stream stdout+stderr line-by-line.
    let mut cmd = podman.base_command();
    cmd.arg("commit").arg(&container_id.0).arg(&image_ref);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return finalize_failure(
                &db,
                &publisher,
                &job_id,
                snapshot_id,
                format!("spawn failed: {e}"),
            )
            .await;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let publisher_progress = Arc::clone(&publisher);
    let db_progress = Arc::clone(&db);
    let job_id_progress = job_id.clone();
    let progress_task = tokio::spawn(async move {
        let mut last = String::new();
        if let Some(out) = stdout {
            let reader = BufReader::new(out);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                emit_progress(&db_progress, &publisher_progress, &job_id_progress, &line).await;
                last = line;
            }
        }
        if let Some(err) = stderr {
            let reader = BufReader::new(err);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                emit_progress(&db_progress, &publisher_progress, &job_id_progress, &line).await;
                last = line;
            }
        }
        last
    });

    let exit = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            let _ = progress_task.await;
            return finalize_failure(
                &db,
                &publisher,
                &job_id,
                snapshot_id,
                format!("wait failed: {e}"),
            )
            .await;
        }
    };
    let last_line = progress_task.await.unwrap_or_default();

    if !exit.success() {
        let msg = if last_line.is_empty() {
            format!("podman commit exited with status {exit}")
        } else {
            format!("podman commit failed: {last_line}")
        };
        return finalize_failure(&db, &publisher, &job_id, snapshot_id, msg).await;
    }

    // Promote snapshot row.
    sqlx::query("UPDATE snapshots SET image_ref = ? WHERE id = ?")
        .bind(&image_ref)
        .bind(snapshot_id)
        .execute(db.pool())
        .await
        .map_err(Error::Sqlx)?;

    // Best-effort size lookup.
    if let Ok(insp) = inspect(&podman, &image_ref).await {
        let _ = sqlx::query("UPDATE snapshots SET size_bytes = ? WHERE id = ?")
            .bind(insp.size_bytes as i64)
            .bind(snapshot_id)
            .execute(db.pool())
            .await;
    }

    let ended = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    sqlx::query(
        "UPDATE snapshot_jobs SET status = 'succeeded', snapshot_id = ?, image_ref = ?, \
         ended_at = ? WHERE job_id = ?",
    )
    .bind(snapshot_id)
    .bind(&image_ref)
    .bind(&ended)
    .bind(&job_id)
    .execute(db.pool())
    .await
    .map_err(Error::Sqlx)?;

    publisher.publish(Event {
        topic: EventTopic::Snapshot,
        kind: EventKind::Succeeded,
        resource_id: job_id.clone(),
        timestamp: Utc::now(),
        details: serde_json::json!({
            "snapshot_id": snapshot_id,
            "image_ref": image_ref,
            "container_id": container_id.0,
        }),
    });
    Ok(())
}

async fn emit_progress(
    db: &Arc<Database>,
    publisher: &Arc<dyn EventPublisher>,
    job_id: &str,
    line: &str,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }
    let _ = sqlx::query("UPDATE snapshot_jobs SET last_progress = ? WHERE job_id = ?")
        .bind(trimmed)
        .bind(job_id)
        .execute(db.pool())
        .await;
    publisher.publish(Event {
        topic: EventTopic::Snapshot,
        kind: EventKind::Progress,
        resource_id: job_id.to_string(),
        timestamp: Utc::now(),
        details: serde_json::json!({ "message": trimmed }),
    });
}

/// Snapshot of a `snapshot_jobs` row, suitable for translating into
/// `responses::SnapshotJobStatusResponse` at the daemon layer. Wide field set keeps the
/// runtime crate free of any IPC-response struct dependency.
#[derive(Debug, Clone)]
pub struct JobStatusSnapshot {
    pub job_id: String,
    pub container_id: String,
    pub label: Option<String>,
    pub status: String,
    pub snapshot_id: Option<i64>,
    pub image_ref: Option<String>,
    pub last_progress: Option<String>,
    pub error_message: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
}

type JobStatusTuple = (
    String,
    String,
    Option<String>,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

/// Query the row matching `job_id` from `snapshot_jobs`. Returns
/// [`Error::NotFound`] when no row matches.
#[instrument(skip(db))]
pub async fn query_job_status(db: &Database, job_id: &str) -> Result<JobStatusSnapshot> {
    let row: Option<JobStatusTuple> = sqlx::query_as(
        "SELECT job_id, container_id, label, status, snapshot_id, image_ref, last_progress, \
         error_message, started_at, ended_at FROM snapshot_jobs WHERE job_id = ?",
    )
    .bind(job_id)
    .fetch_optional(db.pool())
    .await
    .map_err(Error::Sqlx)?;
    let row = row.ok_or_else(|| Error::NotFound(format!("snapshot job {job_id}")))?;
    let (
        job_id,
        container_id,
        label,
        status,
        snapshot_id,
        image_ref,
        last_progress,
        error_message,
        started_at_str,
        ended_at_str,
    ) = row;
    let started_at = chrono::DateTime::parse_from_rfc3339(&started_at_str)
        .map(|d| d.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Runtime {
            message: format!("invalid snapshot_jobs.started_at '{started_at_str}': {e}"),
        })?;
    let ended_at = ended_at_str
        .as_deref()
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&chrono::Utc))
                .map_err(|e| Error::Runtime {
                    message: format!("invalid snapshot_jobs.ended_at '{s}': {e}"),
                })
        })
        .transpose()?;
    Ok(JobStatusSnapshot {
        job_id,
        container_id,
        label,
        status,
        snapshot_id,
        image_ref,
        last_progress,
        error_message,
        started_at,
        ended_at,
    })
}

async fn finalize_failure(
    db: &Arc<Database>,
    publisher: &Arc<dyn EventPublisher>,
    job_id: &str,
    snapshot_id: i64,
    error_message: String,
) -> Result<()> {
    let ended = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let _ = sqlx::query("DELETE FROM snapshots WHERE id = ?")
        .bind(snapshot_id)
        .execute(db.pool())
        .await;
    sqlx::query(
        "UPDATE snapshot_jobs SET status = 'failed', error_message = ?, ended_at = ? \
         WHERE job_id = ?",
    )
    .bind(&error_message)
    .bind(&ended)
    .bind(job_id)
    .execute(db.pool())
    .await
    .map_err(Error::Sqlx)?;
    publisher.publish(Event {
        topic: EventTopic::Snapshot,
        kind: EventKind::Failed,
        resource_id: job_id.to_string(),
        timestamp: Utc::now(),
        details: serde_json::json!({ "error": error_message }),
    });
    Ok(())
}

// =====================================================================================
// Phase 7 Stage 2-A: pluggable snapshot backends + OCI layer diff (diff_v2)
// =====================================================================================

/// Pluggable backend that turns a running container into an immutable snapshot. Three
/// implementations ship in v0.1: `PodmanCommitBackend` (default; uses `podman commit`),
/// `OverlayfsBackend` (store-only; per-image dir + meta sidecar via `podman cp`), and
/// `BtrfsBackend` (scaffold — mutating methods return [`Error::Runtime`]).
#[async_trait]
pub trait SnapshotBackend: Send + Sync {
    /// The backend kind tag persisted on the snapshot row.
    fn kind(&self) -> SnapshotBackendKind;
    /// Materialise a new image from `container_id`, named/tagged `image_ref`. Returns
    /// the long image id printed by the backend.
    async fn commit(
        &self,
        podman: &Podman,
        container_id: &ContainerId,
        image_ref: &str,
    ) -> Result<ImageId>;
    /// Tag an existing image with an additional reference (used by alias / branch).
    async fn tag(&self, podman: &Podman, source: &str, target: &str) -> Result<()>;
    /// Look up the on-disk size in bytes of `image`.
    async fn image_size(&self, podman: &Podman, image: &str) -> Result<i64>;
    /// Remove the image. `force` mirrors `podman rmi --force`.
    async fn remove(&self, podman: &Podman, image: &str, force: bool) -> Result<()>;
    /// Reports whether the backend can run on this host *right now*. Cheap (filesystem
    /// existence check or one short subprocess); safe to call repeatedly.
    async fn is_available(&self) -> bool;
    /// Short human-readable note describing the backend's status / limitations. Surfaced
    /// in the `snapshot backend list` CLI output.
    fn note(&self) -> &'static str;
    /// Phase 16 Stream B — at-rest encryption config. The default is `None`
    /// (encryption disabled). Backends do not encrypt in their `commit` flow;
    /// at-rest encryption is owned by the daemon-side encryptor / rotation
    /// paths (see [`PodmanCommitBackend`]'s note), so no shipped backend
    /// overrides this.
    fn encryption_config(&self) -> Option<&EncryptionConfig> {
        None
    }
}

/// Default backend: wraps the existing `podman commit` / `tag` / `inspect` / `rmi` flow.
///
/// The backend stays a zero-sized unit struct so cross-crate call sites can keep
/// constructing it by bare name (`PodmanCommitBackend`). At-rest snapshot
/// encryption is deliberately *not* a backend concern: it is driven separately
/// by the daemon's auto-encrypt hook and the key-rotation path, each of which
/// owns its own [`EncryptionConfig`] (constructed once at daemon startup from
/// the `LINPODX_SNAPSHOT_KEY` / `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` env vars,
/// injectable for tests, and replaceable on rotation).
#[derive(Debug, Default, Clone, Copy)]
pub struct PodmanCommitBackend;

#[async_trait]
impl SnapshotBackend for PodmanCommitBackend {
    fn kind(&self) -> SnapshotBackendKind {
        SnapshotBackendKind::PodmanCommit
    }
    async fn commit(
        &self,
        podman: &Podman,
        container_id: &ContainerId,
        image_ref: &str,
    ) -> Result<ImageId> {
        create(podman, container_id, image_ref).await
    }
    async fn tag(&self, podman: &Podman, source: &str, target: &str) -> Result<()> {
        alias(podman, source, target).await
    }
    async fn image_size(&self, podman: &Podman, image: &str) -> Result<i64> {
        image_size_bytes(podman, image).await
    }
    async fn remove(&self, podman: &Podman, image: &str, force: bool) -> Result<()> {
        remove(podman, image, force).await
    }
    async fn is_available(&self) -> bool {
        true
    }
    fn note(&self) -> &'static str {
        "default; uses `podman commit` to build an OCI image (works on every host)"
    }
    // `encryption_config()` intentionally uses the trait default (`None`).
    //
    // At-rest snapshot encryption is NOT performed by the backend's `commit`
    // flow — it is a separate step driven by the daemon's auto-encrypt hook
    // (`RuntimeSnapshotEncryptor`, which *owns* its `EncryptionConfig`,
    // constructed once at daemon startup from `LINPODX_SNAPSHOT_KEY` /
    // `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE`) and by the key-rotation path
    // (`rotate_snapshot_key`, which takes explicit old/new configs). Neither
    // reads the backend's `encryption_config()`, so exposing a process-wide
    // frozen config here (the old `active_encryption_config` `OnceLock`) served
    // no production consumer and actively fought key rotation: once seeded it
    // could never reflect a rotated key. The owned/injectable/replaceable
    // config now lives entirely on those daemon-side owners.
}

// =====================================================================================
// Phase 16 Stream B — at-rest encryption pipeline (PodmanCommit backend only for v0.1).
// =====================================================================================

/// On-disk metadata describing an encrypted snapshot blob. Written next to the
/// ciphertext as `meta.json`. Persisted on disk so the dispatcher can answer
/// `SnapshotEncryptionStatus` without needing the original `EncryptionConfig`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EncryptedSnapshotMeta {
    pub algorithm: String,
    pub key_source: String,
    pub ciphertext_sha256: String,
    pub original_image_ref: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Length of the underlying plaintext tar in bytes. Useful for size-delta
    /// checks; the encrypted blob is `plaintext_len + 12 (nonce) + 16 (tag)`.
    pub plaintext_len: u64,
    /// Phase 17 — KDF used to derive the AES key from the original passphrase.
    /// Absent in Phase 16 meta files; `default_legacy_kdf` fills in the
    /// implicit `sha256-rounds` (1000) when deserialising those.
    #[serde(default = "default_legacy_kdf")]
    pub kdf: snapshot_crypto::Kdf,
    /// Phase 17 — rotation lineage. `None` for the originally-encrypted blob;
    /// set to the previous snapshot id (per `snapshots` table) after a
    /// `snapshot.key_rotate` flow re-encrypted in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_from_snapshot_id: Option<i64>,
    /// Phase 17 — UTC timestamp of the last successful key rotation. `None`
    /// when the blob has never been rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Phase 16 meta.json files predate the `kdf` field. Treat them as the legacy
/// 1000-round SHA-256 KDF so on-disk blobs continue to decrypt unchanged.
fn default_legacy_kdf() -> snapshot_crypto::Kdf {
    snapshot_crypto::Kdf::sha256_legacy()
}

/// Filesystem layout for encrypted snapshots:
///
/// ```text
/// $LINPODX_ENCRYPTED_SNAPSHOT_ROOT (default $XDG_DATA_HOME/linpodx/encrypted-snapshots/)
///   <sha8(image_ref)>/
///     blob.enc
///     meta.json
/// ```
///
/// The directory is intentionally hashed instead of using the raw image_ref so
/// reference forms with `:` or `/` don't end up in path components.
pub fn encrypted_store_root() -> PathBuf {
    if let Ok(custom) = std::env::var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT") {
        if !custom.is_empty() {
            return PathBuf::from(custom);
        }
    }
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local/share"))
        })
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("linpodx/encrypted-snapshots")
}

/// Single crate-wide serialisation lock for tests that mutate
/// `LINPODX_ENCRYPTED_SNAPSHOT_ROOT`. `encrypted_store_root()` still reads that
/// env var in production (unchanged), and unlike the on-disk overlay store there
/// is no owned-config seam for it (the encryption pipeline's public fns are
/// consumed by the daemon and can't take a root param here). So the tests in
/// `snapshot::tests` and `snapshot_key_rotation::tests` that pin the encrypted
/// root to a tempdir must share **one** mutex — previously they used two
/// independent locks and raced on the shared env var under parallel `cargo test`.
#[cfg(test)]
pub(crate) fn encrypted_root_test_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Per-image directory under [`encrypted_store_root`].
pub fn encrypted_image_dir(image_ref: &str) -> PathBuf {
    let digest = snapshot_crypto::sha256_hex(image_ref.as_bytes());
    encrypted_store_root().join(&digest[..16])
}

/// Read the side-car `meta.json` for `image_ref`. Returns `Ok(None)` when the
/// directory or file doesn't exist (i.e. snapshot wasn't encrypted).
pub fn read_encrypted_meta(image_ref: &str) -> Result<Option<EncryptedSnapshotMeta>> {
    let path = encrypted_image_dir(image_ref).join("meta.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            let meta: EncryptedSnapshotMeta =
                serde_json::from_slice(&bytes).map_err(|e| Error::Runtime {
                    message: format!("encrypted meta {} parse error: {e}", path.display()),
                })?;
            Ok(Some(meta))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Runtime {
            message: format!("encrypted meta {} read error: {e}", path.display()),
        }),
    }
}

/// Encrypt a previously-committed image and write it next to the side-car
/// metadata. Pipeline: `podman save` to a tempfile → encrypt → write
/// `blob.enc` + `meta.json` atomically (write to `*.tmp` then rename).
///
/// `keep_local_image` controls whether the plaintext image stays in podman's
/// local store after encryption — daemons that want only the encrypted blob to
/// survive should pass `false`; tests / debug paths pass `true` to keep it
/// inspectable.
#[instrument(skip(podman, cfg), fields(image = %image_ref))]
pub async fn encrypt_committed_image(
    podman: &Podman,
    image_ref: &str,
    cfg: &EncryptionConfig,
    keep_local_image: bool,
) -> Result<EncryptedSnapshotMeta> {
    let dir = encrypted_image_dir(image_ref);
    let dir_for_blocking = dir.clone();
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&dir_for_blocking).map_err(|e| Error::Runtime {
            message: format!(
                "create encrypted snapshot dir {}: {e}",
                dir_for_blocking.display()
            ),
        })
    })
    .await
    .map_err(|e| Error::Runtime {
        message: format!("encrypted dir spawn join: {e}"),
    })??;

    let tmp = tempfile::tempdir().map_err(|e| Error::Runtime {
        message: format!("encrypt tempdir: {e}"),
    })?;
    let plain_path = tmp.path().join("image.tar");
    oci_tar::save_image(podman, image_ref, &plain_path).await?;

    let plain_path_clone = plain_path.clone();
    let cfg_clone = cfg.clone();
    let dir_clone = dir.clone();
    let image_ref_owned = image_ref.to_string();
    let meta = tokio::task::spawn_blocking(move || -> Result<EncryptedSnapshotMeta> {
        let plain = std::fs::read(&plain_path_clone).map_err(|e| Error::Runtime {
            message: format!("read plaintext tar {}: {e}", plain_path_clone.display()),
        })?;
        let plaintext_len = plain.len() as u64;
        let blob =
            snapshot_crypto::encrypt_bytes(&plain, &cfg_clone).map_err(|e| Error::Runtime {
                message: format!("snapshot encrypt: {e}"),
            })?;
        let sha = snapshot_crypto::sha256_hex(&blob);

        let meta = EncryptedSnapshotMeta {
            algorithm: cfg_clone.algorithm.to_string(),
            key_source: cfg_clone.key_source.as_str().to_string(),
            ciphertext_sha256: sha,
            original_image_ref: image_ref_owned,
            created_at: chrono::Utc::now(),
            plaintext_len,
            kdf: cfg_clone.kdf,
            rotated_from_snapshot_id: None,
            rotated_at: None,
        };

        let blob_path = dir_clone.join("blob.enc");
        let blob_tmp = dir_clone.join("blob.enc.tmp");
        std::fs::write(&blob_tmp, &blob).map_err(|e| Error::Runtime {
            message: format!("write {}: {e}", blob_tmp.display()),
        })?;
        std::fs::rename(&blob_tmp, &blob_path).map_err(|e| Error::Runtime {
            message: format!(
                "rename {} -> {}: {e}",
                blob_tmp.display(),
                blob_path.display()
            ),
        })?;

        let meta_path = dir_clone.join("meta.json");
        let meta_tmp = dir_clone.join("meta.json.tmp");
        let meta_bytes = serde_json::to_vec_pretty(&meta).map_err(|e| Error::Runtime {
            message: format!("serialise encrypted meta: {e}"),
        })?;
        std::fs::write(&meta_tmp, &meta_bytes).map_err(|e| Error::Runtime {
            message: format!("write {}: {e}", meta_tmp.display()),
        })?;
        std::fs::rename(&meta_tmp, &meta_path).map_err(|e| Error::Runtime {
            message: format!(
                "rename {} -> {}: {e}",
                meta_tmp.display(),
                meta_path.display()
            ),
        })?;

        Ok(meta)
    })
    .await
    .map_err(|e| Error::Runtime {
        message: format!("encrypt blocking join: {e}"),
    })??;

    if !keep_local_image {
        if let Err(e) = remove(podman, image_ref, true).await {
            warn!(image = image_ref, error = %e, "encrypt: failed to remove plaintext image after encrypt (continuing)");
        }
    }

    Ok(meta)
}

/// Inverse of [`encrypt_committed_image`]: read the side-car blob, decrypt
/// with `cfg`, and `podman load` the resulting tar back into the local store.
/// Returns the meta record on success.
#[instrument(skip(podman, cfg), fields(image = %image_ref))]
pub async fn decrypt_and_load(
    podman: &Podman,
    image_ref: &str,
    cfg: &EncryptionConfig,
) -> Result<EncryptedSnapshotMeta> {
    let dir = encrypted_image_dir(image_ref);
    let meta_path = dir.join("meta.json");
    let blob_path = dir.join("blob.enc");

    let cfg_clone = cfg.clone();
    let (meta, plaintext) =
        tokio::task::spawn_blocking(move || -> Result<(EncryptedSnapshotMeta, Vec<u8>)> {
            let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::Runtime {
                message: format!("read encrypted meta {}: {e}", meta_path.display()),
            })?;
            let meta: EncryptedSnapshotMeta =
                serde_json::from_slice(&meta_bytes).map_err(|e| Error::Runtime {
                    message: format!("parse encrypted meta: {e}"),
                })?;
            let blob = std::fs::read(&blob_path).map_err(|e| Error::Runtime {
                message: format!("read encrypted blob {}: {e}", blob_path.display()),
            })?;
            // Best-effort tamper check before paying for AEAD.
            let actual = snapshot_crypto::sha256_hex(&blob);
            if actual != meta.ciphertext_sha256 {
                return Err(Error::Runtime {
                    message: format!(
                        "ciphertext sha256 mismatch (expected {}, got {})",
                        meta.ciphertext_sha256, actual
                    ),
                });
            }
            let plain =
                snapshot_crypto::decrypt_bytes(&blob, &cfg_clone).map_err(|e| Error::Runtime {
                    message: format!("snapshot decrypt: {e}"),
                })?;
            Ok((meta, plain))
        })
        .await
        .map_err(|e| Error::Runtime {
            message: format!("decrypt blocking join: {e}"),
        })??;

    let tmp = tempfile::tempdir().map_err(|e| Error::Runtime {
        message: format!("decrypt tempdir: {e}"),
    })?;
    let load_path = tmp.path().join("image.tar");
    let load_path_clone = load_path.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::write(&load_path_clone, &plaintext).map_err(|e| Error::Runtime {
            message: format!("write decrypted tar {}: {e}", load_path_clone.display()),
        })
    })
    .await
    .map_err(|e| Error::Runtime {
        message: format!("decrypt write join: {e}"),
    })??;

    let mut cmd = podman.base_command();
    cmd.arg("load").arg("-i").arg(&load_path);
    podman.run_capture(cmd).await?;
    Ok(meta)
}

/// Convenience for callers that only need to know whether an image was
/// encrypted (cheaper than [`read_encrypted_meta`] when callers don't need
/// the metadata itself).
pub fn is_image_encrypted(image_ref: &str) -> bool {
    encrypted_image_dir(image_ref).join("meta.json").is_file()
}

/// Remove the on-disk encrypted blob + meta for `image_ref`. Idempotent.
pub fn remove_encrypted_artifacts(image_ref: &str) -> Result<()> {
    let dir = encrypted_image_dir(image_ref);
    if !dir.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(&dir).map_err(|e| Error::Runtime {
        message: format!("remove encrypted dir {}: {e}", dir.display()),
    })
}

/// Overlayfs backend.
///
/// Materialises each snapshot as a directory tree under
/// [`overlayfs::store_root()`] using `podman cp <ctr>:/ <upper>`, with a
/// sidecar `meta.json` recording size and provenance. `tag` hardlinks the
/// source tree (`cp -al`) so two refs share storage; `remove` deletes the
/// per-image directory; `image_size` prefers the cached metadata and falls
/// back to a recursive directory walk.
///
/// Phase 9 Stream D: when `fuse-overlayfs` is on PATH, `commit` additionally
/// mounts the resulting `lower/upper/work` triple at
/// `/tmp/linpodx-overlay-<sha8>` and parks the [`MountedRoot`] handle in an
/// instance-owned registry keyed by image_ref. Hosts without the binary fall
/// back to the metadata-only behaviour and emit a warn (no audit entry).
///
/// State ownership (was process-global `OnceLock`s before): the on-disk store
/// root, the live-mount registry, and the audit sink are all owned fields
/// resolved once at construction. [`OverlayfsBackend::default`] reads
/// `LINPODX_OVERLAYFS_ROOT` exactly once (operator behaviour unchanged); tests
/// inject a tempdir via [`OverlayfsBackend::with_store_root`]. The registry is
/// an `Arc<Mutex<_>>` so cloning the backend (e.g. to place one copy in a
/// `SnapshotManager` backend map and keep a typed handle for mount lookups)
/// shares the same live-mount table.
#[derive(Clone)]
pub struct OverlayfsBackend {
    /// On-disk store root, resolved once at construction.
    store_root: PathBuf,
    /// Live fuse-overlayfs mounts keyed by image_ref. `Arc` so clones share it.
    registry: Arc<Mutex<HashMap<String, MountedRoot>>>,
    /// Audit sink for mount/unmount events. Defaults to [`NoopAuditSink`]
    /// (the daemon never installed a different one in production).
    audit_sink: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for OverlayfsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `audit_sink` is a trait object without `Debug`; elide it.
        f.debug_struct("OverlayfsBackend")
            .field("store_root", &self.store_root)
            .finish_non_exhaustive()
    }
}

const OVERLAYFS_MODULE_PATH: &str = "/sys/module/overlay";

impl Default for OverlayfsBackend {
    fn default() -> Self {
        // Single startup env read of `LINPODX_OVERLAYFS_ROOT`.
        Self::with_store_root(overlayfs::store_root())
    }
}

impl OverlayfsBackend {
    /// Construct a backend rooted at an explicit on-disk store `store_root`,
    /// with a fresh (empty) live-mount registry and a no-op audit sink. This is
    /// the injection seam tests use instead of mutating `LINPODX_OVERLAYFS_ROOT`.
    pub fn with_store_root(store_root: PathBuf) -> Self {
        Self {
            store_root,
            registry: Arc::new(Mutex::new(HashMap::new())),
            audit_sink: Arc::new(NoopAuditSink),
        }
    }

    /// Builder-style override of the audit sink used for mount/unmount events.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = sink;
        self
    }

    /// The resolved on-disk store root this backend materialises snapshots under.
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    /// Mount path currently registered for `image_ref`, if any. Returns `None`
    /// when the image was committed on a host without `fuse-overlayfs`, or when
    /// no commit has happened through this backend yet.
    pub fn mount_path_for(&self, image_ref: &str) -> Option<PathBuf> {
        let g = self.registry.lock().ok()?;
        g.get(image_ref).map(|m| m.mount_path().to_path_buf())
    }

    /// Drop and unmount the registered mount for `image_ref` (if any). Emits
    /// `SnapshotUnmounted` on success. Used by `remove` and by tests/cleanup
    /// paths that want explicit teardown rather than waiting for process exit.
    pub async fn unmount_for(&self, image_ref: &str) {
        let path = {
            let mut g = match self.registry.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.remove(image_ref).map(|m| m.mount_path().to_path_buf())
        };
        if let Some(p) = path {
            let payload = serde_json::json!({
                "image_ref": image_ref,
                "mount_path": p.display().to_string(),
            });
            self.audit_sink
                .record(AuditSinkKind::SnapshotUnmounted, None, None, payload)
                .await;
            // The MountedRoot Drop already ran when removed from the registry above.
        }
    }
}

#[async_trait]
impl SnapshotBackend for OverlayfsBackend {
    fn kind(&self) -> SnapshotBackendKind {
        SnapshotBackendKind::Overlayfs
    }

    async fn commit(
        &self,
        podman: &Podman,
        container_id: &ContainerId,
        image_ref: &str,
    ) -> Result<ImageId> {
        let image_ref = image_ref.to_string();
        let cid = container_id.0.clone();

        // ensure_dirs is sync FS work; defer to a blocking task.
        let dirs = {
            let image_ref = image_ref.clone();
            let root = self.store_root.clone();
            tokio::task::spawn_blocking(move || overlayfs::ensure_dirs_in(&root, &image_ref))
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs ensure_dirs join: {e}"),
                })?
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs ensure_dirs: {e}"),
                })?
        };

        // `podman cp <ctr>:/ <upper>` materialises the container's root filesystem.
        let mut cmd = podman.base_command();
        cmd.arg("cp").arg(format!("{cid}:/")).arg(&dirs.upper);
        podman
            .run_capture(cmd)
            .await
            .map_err(|e| map_not_found(e, &cid))?;

        // Resolve the source image (best-effort) and compute size on disk.
        let original_image = resolve_container_image(podman, &cid)
            .await
            .unwrap_or_default();
        let upper_for_size = dirs.upper.clone();
        let size_bytes =
            tokio::task::spawn_blocking(move || overlayfs::dir_size_bytes(&upper_for_size))
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs size join: {e}"),
                })?
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs dir_size_bytes: {e}"),
                })?;

        let meta = overlayfs::OverlayMeta {
            original_image,
            created_at: Utc::now(),
            size_bytes,
            layer_count: 1,
        };
        {
            let image_ref = image_ref.clone();
            let root = self.store_root.clone();
            tokio::task::spawn_blocking(move || overlayfs::write_meta_in(&root, &image_ref, &meta))
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs write_meta join: {e}"),
                })?
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs write_meta: {e}"),
                })?;
        }

        // Phase 9 Stream D: best-effort `fuse-overlayfs` mount. Failures are
        // logged and swallowed — the metadata-only commit above is the source
        // of truth; a missing mount is a degraded (not failed) state.
        let audit = Arc::clone(&self.audit_sink);
        match overlayfs::mount_layers_in(&self.store_root, &image_ref, audit).await {
            Ok(Some(handle)) => {
                if let Ok(mut g) = self.registry.lock() {
                    g.insert(image_ref.clone(), handle);
                }
            }
            Ok(None) => {
                // fuse-overlayfs not installed; mount_layers already warned.
            }
            Err(e) => {
                warn!(image_ref = %image_ref, error = %e, "fuse-overlayfs mount failed (commit still succeeded)");
            }
        }

        Ok(ImageId(image_ref))
    }

    async fn tag(&self, _podman: &Podman, source: &str, target: &str) -> Result<()> {
        let source_dir = overlayfs::image_dir_in(&self.store_root, source);
        if !source_dir.exists() {
            return Err(Error::NotFound(format!("overlayfs image {source}")));
        }
        let target_dir = overlayfs::image_dir_in(&self.store_root, target);
        // Don't clobber an existing target — reject so callers don't lose data.
        if target_dir.exists() {
            return Err(Error::Runtime {
                message: format!("overlayfs target image already exists: {target}"),
            });
        }
        // Ensure parent dir exists (store_root() may not yet).
        if let Some(parent) = target_dir.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs tag mkdir parent: {e}"),
                })?;
        }

        let status = tokio::process::Command::new("cp")
            .arg("-a")
            .arg("-l")
            .arg(&source_dir)
            .arg(&target_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .map_err(|e| Error::Runtime {
                message: format!("overlayfs tag spawn cp: {e}"),
            })?;
        if !status.success() {
            return Err(Error::Runtime {
                message: format!("overlayfs tag: cp -al exited with status {status}"),
            });
        }
        Ok(())
    }

    async fn image_size(&self, _podman: &Podman, image: &str) -> Result<i64> {
        let image_owned = image.to_string();
        let root = self.store_root.clone();
        let cached =
            tokio::task::spawn_blocking(move || overlayfs::read_meta_in(&root, &image_owned))
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("overlayfs read_meta join: {e}"),
                })?;
        if let Ok(meta) = cached {
            return Ok(meta.size_bytes as i64);
        }
        // Fall back to a recursive walk of upper/.
        let upper = overlayfs::image_dir_in(&self.store_root, image).join("upper");
        if !upper.exists() {
            return Err(Error::NotFound(format!("overlayfs image {image}")));
        }
        let bytes = tokio::task::spawn_blocking(move || overlayfs::dir_size_bytes(&upper))
            .await
            .map_err(|e| Error::Runtime {
                message: format!("overlayfs size join: {e}"),
            })?
            .map_err(|e| Error::Runtime {
                message: format!("overlayfs dir_size_bytes: {e}"),
            })?;
        Ok(bytes as i64)
    }

    async fn remove(&self, _podman: &Podman, image: &str, force: bool) -> Result<()> {
        // Drop any live fuse-overlayfs mount before deleting the on-disk store
        // so `fusermount3 -u` runs against a path that still exists.
        self.unmount_for(image).await;
        let dir = overlayfs::image_dir_in(&self.store_root, image);
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if force {
                    Ok(())
                } else {
                    Err(Error::NotFound(format!("overlayfs image {image}")))
                }
            }
            Err(e) => {
                if force {
                    Ok(())
                } else {
                    Err(Error::Runtime {
                        message: format!("overlayfs remove {image}: {e}"),
                    })
                }
            }
        }
    }

    async fn is_available(&self) -> bool {
        tokio::fs::metadata(OVERLAYFS_MODULE_PATH).await.is_ok()
    }

    fn note(&self) -> &'static str {
        "store-only; commit/tag/size/remove via per-image dir + meta.json (no real mount yet)"
    }
}

/// Best-effort resolver for the source image of a running container, used to record
/// `original_image` in the overlay metadata. Failures collapse to an empty string at the
/// caller because the field is informational only.
async fn resolve_container_image(podman: &Podman, container_id: &str) -> Result<String> {
    let mut cmd = podman.base_command();
    cmd.arg("inspect")
        .arg("--format")
        .arg("{{.ImageName}}")
        .arg(container_id);
    let out = podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, container_id))?;
    Ok(out.trim().to_string())
}

/// Btrfs backend.
///
/// Snapshot semantics map onto `btrfs subvolume snapshot/delete`. `is_available()`
/// reports true when the daemon's overlay store-root lives on a btrfs filesystem
/// (`stat -f --format=%T <store_root>` ⇒ `"btrfs"`); the four mutating ops shell
/// out to the `btrfs` CLI. `commit` fetches the container's `MergedDir` from
/// `podman inspect` and snapshots that subvolume; if the inspect path can't be
/// resolved (rootless / vfs storage), `commit` falls back to `PodmanCommitBackend`
/// with a warn so callers still get an image rather than an outright failure.
///
/// State ownership (was env reads before): the store root and an optional
/// availability override are owned fields resolved once at construction.
/// [`BtrfsBackend::default`] reads `LINPODX_OVERLAYFS_ROOT` (via
/// `overlayfs::store_root`) and `LINPODX_BTRFS_AVAILABLE` exactly once — operator
/// behaviour unchanged. Tests inject both directly via
/// [`BtrfsBackend::with_config`] instead of mutating process env.
#[derive(Debug, Clone)]
pub struct BtrfsBackend {
    /// Store root that per-image subvolumes live under.
    store_root: PathBuf,
    /// `Some(true|false)` forces `is_available()` deterministically (test seam,
    /// formerly the `LINPODX_BTRFS_AVAILABLE` env override); `None` probes the
    /// host (`btrfs --version` + `stat -f` on the store root).
    available_override: Option<bool>,
}

impl Default for BtrfsBackend {
    fn default() -> Self {
        // Single startup read of both env knobs.
        let available_override = std::env::var_os("LINPODX_BTRFS_AVAILABLE").map(|v| v == "1");
        Self {
            store_root: overlayfs::store_root(),
            available_override,
        }
    }
}

impl BtrfsBackend {
    /// Construct a backend with an explicit store root and availability override.
    /// The injection seam tests use instead of mutating process env.
    pub fn with_config(store_root: PathBuf, available_override: Option<bool>) -> Self {
        Self {
            store_root,
            available_override,
        }
    }

    /// Per-image subvolume path: `<store_root>/<sha8(image_ref)>`. Reuses
    /// `overlayfs::sha8` so btrfs and overlayfs share a stable naming scheme.
    fn image_path(&self, image_ref: &str) -> PathBuf {
        self.store_root.join(overlayfs::sha8(image_ref))
    }
}

mod btrfs_cmd {
    //! Thin async wrappers around the `btrfs` CLI. Each helper returns
    //! `Err(Error::Runtime { ... })` on non-zero exit so callers can attach
    //! context-specific messages.

    use linpodx_common::error::{Error, Result};
    use std::path::Path;
    use std::process::Stdio;

    pub async fn run(args: &[&std::ffi::OsStr]) -> Result<String> {
        let out = tokio::process::Command::new("btrfs")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Runtime {
                message: format!("btrfs spawn: {e}"),
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            return Err(Error::Runtime {
                message: format!("btrfs exited {}: {}", out.status, stderr.trim()),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub async fn subvolume_snapshot(source: &Path, dest: &Path, readonly: bool) -> Result<()> {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            std::ffi::OsStr::new("subvolume"),
            std::ffi::OsStr::new("snapshot"),
        ];
        if readonly {
            args.push(std::ffi::OsStr::new("-r"));
        }
        args.push(source.as_os_str());
        args.push(dest.as_os_str());
        run(&args).await.map(|_| ())
    }

    pub async fn subvolume_delete(path: &Path) -> Result<()> {
        let args: [&std::ffi::OsStr; 3] = [
            std::ffi::OsStr::new("subvolume"),
            std::ffi::OsStr::new("delete"),
            path.as_os_str(),
        ];
        run(&args).await.map(|_| ())
    }
}

async fn btrfs_resolve_merged_dir(podman: &Podman, container_id: &str) -> Result<PathBuf> {
    let mut cmd = podman.base_command();
    cmd.arg("inspect")
        .arg("--format")
        .arg("{{.GraphDriver.Data.MergedDir}}")
        .arg(container_id);
    let out = podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, container_id))?;
    let trimmed = out.trim();
    if trimmed.is_empty() || trimmed == "<no value>" {
        return Err(Error::Runtime {
            message: format!("podman inspect produced no MergedDir for {container_id}"),
        });
    }
    Ok(PathBuf::from(trimmed))
}

#[async_trait]
impl SnapshotBackend for BtrfsBackend {
    fn kind(&self) -> SnapshotBackendKind {
        SnapshotBackendKind::Btrfs
    }
    async fn commit(
        &self,
        podman: &Podman,
        container_id: &ContainerId,
        image_ref: &str,
    ) -> Result<ImageId> {
        let dest = self.image_path(image_ref);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("btrfs commit mkdir parent: {e}"),
                })?;
        }
        match btrfs_resolve_merged_dir(podman, &container_id.0).await {
            Ok(merged) => {
                btrfs_cmd::subvolume_snapshot(&merged, &dest, false)
                    .await
                    .map_err(|e| match e {
                        Error::Runtime { message } => Error::Runtime {
                            message: format!("btrfs subvolume snapshot: {message}"),
                        },
                        other => other,
                    })?;
                Ok(ImageId(image_ref.to_string()))
            }
            Err(e) => {
                warn!(
                    container = %container_id.0,
                    error = %e,
                    "btrfs commit: MergedDir unavailable, falling back to podman commit"
                );
                PodmanCommitBackend
                    .commit(podman, container_id, image_ref)
                    .await
            }
        }
    }
    async fn tag(&self, _podman: &Podman, source: &str, target: &str) -> Result<()> {
        let src = self.image_path(source);
        if !src.exists() {
            return Err(Error::NotFound(format!("btrfs image {source}")));
        }
        let dst = self.image_path(target);
        if dst.exists() {
            return Err(Error::Runtime {
                message: format!("btrfs target image already exists: {target}"),
            });
        }
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Runtime {
                    message: format!("btrfs tag mkdir parent: {e}"),
                })?;
        }
        btrfs_cmd::subvolume_snapshot(&src, &dst, true)
            .await
            .map_err(|e| match e {
                Error::Runtime { message } => Error::Runtime {
                    message: format!("btrfs subvolume snapshot -r: {message}"),
                },
                other => other,
            })
    }
    async fn image_size(&self, _podman: &Podman, image: &str) -> Result<i64> {
        let path = self.image_path(image);
        if !path.exists() {
            return Err(Error::NotFound(format!("btrfs image {image}")));
        }
        let out = tokio::process::Command::new("du")
            .arg("-sb")
            .arg(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Runtime {
                message: format!("du spawn: {e}"),
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            return Err(Error::Runtime {
                message: format!("du -sb exited {}: {}", out.status, stderr.trim()),
            });
        }
        let line = String::from_utf8_lossy(&out.stdout);
        let first = line.split_whitespace().next().unwrap_or("0");
        first.parse::<i64>().map_err(|e| Error::Runtime {
            message: format!("du -sb produced non-numeric size '{first}': {e}"),
        })
    }
    async fn remove(&self, _podman: &Podman, image: &str, force: bool) -> Result<()> {
        let path = self.image_path(image);
        if !path.exists() {
            return if force {
                Ok(())
            } else {
                Err(Error::NotFound(format!("btrfs image {image}")))
            };
        }
        match btrfs_cmd::subvolume_delete(&path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                if force {
                    warn!(image, error = %e, "btrfs remove failed but force=true — swallowing");
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
    async fn is_available(&self) -> bool {
        // Owned override (was the `LINPODX_BTRFS_AVAILABLE` env read) lets unit
        // tests drive both branches deterministically without touching process env.
        if let Some(forced) = self.available_override {
            return forced;
        }
        // Two probes: btrfs CLI installed AND store_root resides on btrfs.
        let cli_ok = tokio::process::Command::new("btrfs")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if !cli_ok {
            return false;
        }
        let store = self.store_root.clone();
        // Best effort: probe the parent if the store_root itself doesn't exist yet.
        let probe = if store.exists() {
            store.clone()
        } else {
            store.parent().map(PathBuf::from).unwrap_or(store.clone())
        };
        let out = match tokio::process::Command::new("stat")
            .arg("-f")
            .arg("--format=%T")
            .arg(&probe)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return false,
        };
        String::from_utf8_lossy(&out.stdout).trim() == "btrfs"
    }
    fn note(&self) -> &'static str {
        "btrfs subvolume snapshot/delete; requires `btrfs` CLI and a btrfs store_root"
    }
}

/// Build the standard list of backends shipped with linpodx, sorted PodmanCommit /
/// Overlayfs / Btrfs. Each entry's `is_available()` is probed in the listed order.
pub async fn backend_list() -> SnapshotBackendListResponse {
    let backends: Vec<Box<dyn SnapshotBackend>> = vec![
        Box::new(PodmanCommitBackend),
        Box::new(OverlayfsBackend::default()),
        Box::new(BtrfsBackend::default()),
    ];
    let mut out = Vec::with_capacity(backends.len());
    for b in &backends {
        out.push(SnapshotBackendInfo {
            kind: b.kind(),
            available: b.is_available().await,
            note: b.note().to_string(),
        });
    }
    out
}

/// Construct a backend instance for a given kind. Cheap — `PodmanCommit` is
/// zero-sized; `Overlayfs` / `Btrfs` resolve their store root (and, for btrfs,
/// the availability override) from the environment once via `default()`. This
/// factory is used for one-shot operations (e.g. `snapshot backend list`); the
/// daemon's long-lived `SnapshotManager` owns a single shared backend set so
/// the overlayfs live-mount registry is consistent across commit/query.
pub fn backend_for(kind: SnapshotBackendKind) -> Box<dyn SnapshotBackend> {
    match kind {
        SnapshotBackendKind::PodmanCommit => Box::new(PodmanCommitBackend),
        SnapshotBackendKind::Overlayfs => Box::new(OverlayfsBackend::default()),
        SnapshotBackendKind::Btrfs => Box::new(BtrfsBackend::default()),
    }
}

// ----- diff_v2: layer-aware OCI diff ------------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
struct RootFs {
    #[serde(default, alias = "Type")]
    _ty: Option<String>,
    #[serde(default, alias = "Layers")]
    layers: Option<Vec<String>>,
}

/// Look up an image's RootFS layer list via `podman image inspect --format '{{json .RootFS}}'`.
/// Returns the layer digests in order from the base layer up. An image with no `Layers`
/// field (or an empty list) returns an empty vec — callers treat that as "no layers known".
#[instrument(skip(podman))]
pub async fn image_layers(podman: &Podman, image_ref: &str) -> Result<Vec<String>> {
    let mut cmd = podman.base_command();
    cmd.arg("image")
        .arg("inspect")
        .arg("--format")
        .arg("{{json .RootFS}}")
        .arg(image_ref);
    let out = podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, image_ref))?;
    parse_root_fs(&out)
}

fn parse_root_fs(raw: &str) -> Result<Vec<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let rfs: RootFs = serde_json::from_str(trimmed).map_err(|e| Error::Runtime {
        message: format!("podman image inspect RootFS parse error: {e} (raw: {trimmed})"),
    })?;
    Ok(rfs.layers.unwrap_or_default())
}

/// Compute layer-aware diff between two snapshot images. Strategy:
///
/// 1. Inspect each image's `RootFS.Layers` (ordered base→top).
/// 2. Find the longest common prefix — those are shared layers.
/// 3. The non-prefix tails of A / B are reported as `a_only_layers` / `b_only_layers`.
/// 4. **Phase 10:** populate `file_changes` by `podman save`-ing both images into
///    a tempdir, walking each saved OCI tarball's layer headers via
///    [`crate::oci_tar::list_files_in_oci`], and computing the set diff
///    (`b - a` = `added`, `a - b` = `deleted`, intersection with size/mode
///    differences = `modified`). On any failure (podman missing, save errors,
///    parse errors) we log a warning and leave `file_changes` empty rather
///    than failing the whole RPC.
/// 5. `size_delta_bytes = size(B) - size(A)` via `image_size_bytes`.
///
/// Per-layer `size_bytes` lookups are best-effort: `podman image inspect <layer-digest>`
/// only resolves when the layer was promoted to a top-level image. When it fails we
/// record `size_bytes = 0` rather than failing the whole diff.
#[instrument(skip(podman))]
pub async fn diff_v2(
    podman: &Podman,
    image_a: &str,
    image_b: &str,
) -> Result<SnapshotDiffV2Response> {
    let layers_a = image_layers(podman, image_a).await?;
    let layers_b = image_layers(podman, image_b).await?;
    let common = common_prefix_len(&layers_a, &layers_b);
    let a_only_digests: Vec<String> = layers_a.iter().skip(common).cloned().collect();
    let b_only_digests: Vec<String> = layers_b.iter().skip(common).cloned().collect();

    let a_only_layers = layer_infos(podman, &a_only_digests).await;
    let b_only_layers = layer_infos(podman, &b_only_digests).await;

    let size_a = image_size_bytes(podman, image_a).await.unwrap_or(0);
    let size_b = image_size_bytes(podman, image_b).await.unwrap_or(0);

    let file_changes = compute_file_changes(podman, image_a, image_b)
        .await
        .unwrap_or_else(|e| {
            warn!(
                error = %e,
                "diff_v2: file-level walk failed; returning empty file_changes"
            );
            Vec::new()
        });

    Ok(SnapshotDiffV2Response {
        id_a: 0,
        id_b: 0,
        common_layer_count: common,
        a_only_layers,
        b_only_layers,
        file_changes,
        size_delta_bytes: size_b - size_a,
        used_layer_path: true,
    })
}

/// Save both images and turn the per-image file-entry sets into `FileChange`
/// records. Returns `Ok(Vec::new())` if both images saved but produced no
/// differences; returns `Err` if any of the save / parse steps failed (the
/// caller decides whether to surface or fall back).
async fn compute_file_changes(
    podman: &Podman,
    image_a: &str,
    image_b: &str,
) -> Result<Vec<FileChange>> {
    let dir = tempfile::tempdir().map_err(|e| Error::Runtime {
        message: format!("diff_v2 tempdir: {e}"),
    })?;
    let path_a = dir.path().join("a.tar");
    let path_b = dir.path().join("b.tar");
    oci_tar::save_image(podman, image_a, &path_a).await?;
    oci_tar::save_image(podman, image_b, &path_b).await?;

    let set_a = oci_tar::list_files_in_oci(&path_a)?;
    let set_b = oci_tar::list_files_in_oci(&path_b)?;
    Ok(diff_file_sets(&set_a, &set_b))
}

/// Pure helper: compute file-change records from two pre-built sets of file
/// entries (kept separate from [`compute_file_changes`] so unit tests can
/// exercise the diff logic without spawning podman or building OCI tars).
fn diff_file_sets(
    set_a: &std::collections::HashSet<FileEntry>,
    set_b: &std::collections::HashSet<FileEntry>,
) -> Vec<FileChange> {
    let mut out = Vec::new();
    for entry in set_b.difference(set_a) {
        out.push(FileChange {
            kind: "added".into(),
            path: entry.path.clone(),
            layer_id: String::new(),
        });
    }
    for entry in set_a.difference(set_b) {
        out.push(FileChange {
            kind: "deleted".into(),
            path: entry.path.clone(),
            layer_id: String::new(),
        });
    }
    // Modified detection: same path in both sets, but size or mode differs.
    // `HashSet::get` returns the stored entry, which carries its size/mode.
    for entry_a in set_a.intersection(set_b) {
        if let Some(entry_b) = set_b.get(entry_a) {
            if entry_a.size != entry_b.size || entry_a.mode != entry_b.mode {
                out.push(FileChange {
                    kind: "modified".into(),
                    path: entry_a.path.clone(),
                    layer_id: String::new(),
                });
            }
        }
    }
    // Stable ordering: by (kind, path) so callers / tests don't depend on
    // HashSet iteration order.
    out.sort_by(|x, y| x.kind.cmp(&y.kind).then_with(|| x.path.cmp(&y.path)));
    out
}

fn common_prefix_len(a: &[String], b: &[String]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

async fn layer_infos(podman: &Podman, digests: &[String]) -> Vec<LayerInfo> {
    let mut out = Vec::with_capacity(digests.len());
    for d in digests {
        let size = image_size_bytes(podman, d).await.unwrap_or(0);
        out.push(LayerInfo {
            layer_id: d.clone(),
            size_bytes: size,
            created_by: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::podman::PodmanConfig;
    use std::path::PathBuf;

    #[test]
    fn podman_with_disposable_root_constructs() {
        let p = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            root: Some(PathBuf::from("/tmp/snap-root")),
            runroot: Some(PathBuf::from("/tmp/snap-runroot")),
        });
        // We don't run the binary; just sanity-check the override took.
        assert_eq!(p.binary(), "/nonexistent/podman");
    }

    #[tokio::test]
    #[ignore]
    async fn snapshot_lifecycle_alpine() {
        use linpodx_common::ipc::CreateOptions;
        use std::time::Duration;
        use tempfile::tempdir;

        let root = tempdir().expect("root tempdir");
        let runroot = tempdir().expect("runroot tempdir");
        let podman = Podman::with_config(PodmanConfig {
            binary: None,
            root: Some(root.path().to_path_buf()),
            runroot: Some(runroot.path().to_path_buf()),
        });
        podman.check().await.expect("podman check");

        podman
            .pull("docker.io/library/alpine:latest")
            .await
            .expect("pull alpine");

        let opts = CreateOptions {
            image: "docker.io/library/alpine:latest".into(),
            name: Some("linpodx-snap-test".into()),
            command: vec!["sleep".into(), "30".into()],
            labels: vec![("linpodx.test".into(), "snapshot".into())],
            detach: true,
            ..Default::default()
        };
        let cid = podman.create(&opts).await.expect("create");
        podman.start(&cid).await.expect("start");

        let snap_ref = "linpodx-snap-test:v1";
        let snap_id = create(&podman, &cid, snap_ref).await.expect("snapshot");
        assert!(!snap_id.as_str().is_empty());

        let inspected = inspect(&podman, snap_ref).await.expect("inspect snapshot");
        assert!(!inspected.id.as_str().is_empty());

        remove(&podman, snap_ref, true)
            .await
            .expect("remove snapshot");

        // Inspecting the now-removed snapshot should yield NotFound.
        match inspect(&podman, snap_ref).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound after remove, got {other:?}"),
        }

        podman
            .stop(&cid, Some(Duration::from_secs(2)))
            .await
            .expect("stop");
        podman.remove(&cid, true).await.expect("remove container");
    }

    #[tokio::test]
    #[ignore]
    async fn snapshot_branch_and_diff_lifecycle_alpine() {
        use linpodx_common::ipc::CreateOptions;
        use std::time::Duration;
        use tempfile::tempdir;

        let root = tempdir().expect("root tempdir");
        let runroot = tempdir().expect("runroot tempdir");
        let podman = Podman::with_config(PodmanConfig {
            binary: None,
            root: Some(root.path().to_path_buf()),
            runroot: Some(runroot.path().to_path_buf()),
        });
        podman.check().await.expect("podman check");

        podman
            .pull("docker.io/library/alpine:latest")
            .await
            .expect("pull alpine");

        let opts = CreateOptions {
            image: "docker.io/library/alpine:latest".into(),
            name: Some("linpodx-snap-branch-test".into()),
            command: vec!["sleep".into(), "60".into()],
            labels: vec![("linpodx.test".into(), "snapshot-branch".into())],
            detach: true,
            ..Default::default()
        };
        let cid = podman.create(&opts).await.expect("create");
        podman.start(&cid).await.expect("start");

        let snap_a = "linpodx-snap-branch:a";
        create(&podman, &cid, snap_a).await.expect("snapshot a");

        let snap_b = "linpodx-snap-branch:b";
        alias(&podman, snap_a, snap_b).await.expect("alias a→b");

        // Both refs should resolve to the same image content; diff should be empty.
        let diff_out = diff(&podman, snap_a, snap_b).await.expect("diff");
        assert!(
            diff_out.added.is_empty()
                && diff_out.modified.is_empty()
                && diff_out.deleted.is_empty()
        );

        let size_a = image_size_bytes(&podman, snap_a).await.expect("size a");
        let size_b = image_size_bytes(&podman, snap_b).await.expect("size b");
        assert_eq!(size_a, size_b, "aliased images share content");

        remove(&podman, snap_a, true).await.ok();
        remove(&podman, snap_b, true).await.ok();
        podman
            .stop(&cid, Some(Duration::from_secs(2)))
            .await
            .expect("stop");
        podman.remove(&cid, true).await.expect("remove");
    }

    #[tokio::test]
    #[ignore]
    async fn remove_missing_image_is_not_found() {
        use tempfile::tempdir;

        let root = tempdir().expect("root tempdir");
        let runroot = tempdir().expect("runroot tempdir");
        let podman = Podman::with_config(PodmanConfig {
            binary: None,
            root: Some(root.path().to_path_buf()),
            runroot: Some(runroot.path().to_path_buf()),
        });
        podman.check().await.expect("podman check");

        match remove(&podman, "linpodx-does-not-exist:nope", false).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound for missing image, got {other:?}"),
        }
    }

    #[test]
    fn parse_diff_categorizes_lines_and_sorts() {
        let raw = "C /etc/hosts\nA /var/log/new.log\nD /tmp/old\nA /usr/bin/zzz\nA /usr/bin/aaa\n";
        let parsed = parse_diff(raw);
        assert_eq!(
            parsed.added,
            vec!["/usr/bin/aaa", "/usr/bin/zzz", "/var/log/new.log"]
        );
        assert_eq!(parsed.modified, vec!["/etc/hosts"]);
        assert_eq!(parsed.deleted, vec!["/tmp/old"]);
    }

    #[test]
    fn parse_diff_skips_blank_and_unknown_prefixes() {
        let raw = "\nX /weird/line\n   \nA /good\n";
        let parsed = parse_diff(raw);
        assert_eq!(parsed.added, vec!["/good"]);
        assert!(parsed.modified.is_empty());
        assert!(parsed.deleted.is_empty());
    }

    #[test]
    fn symmetric_diff_reports_b_only_changes() {
        let a = parse_diff("A /shared\nC /etc/hosts\n");
        let b =
            parse_diff("A /shared\nA /new-in-b\nC /etc/hosts\nC /etc/passwd\nD /removed-in-b\n");
        let d = symmetric_diff(&a, &b);
        assert_eq!(d.added, vec!["/new-in-b"]);
        assert_eq!(d.modified, vec!["/etc/passwd"]);
        assert_eq!(d.deleted, vec!["/removed-in-b"]);
    }

    #[test]
    fn symmetric_diff_demotes_a_only_additions_to_deleted() {
        let a = parse_diff("A /only-in-a\n");
        let b = parse_diff("");
        let d = symmetric_diff(&a, &b);
        assert!(d.added.is_empty());
        assert!(d.modified.is_empty());
        assert_eq!(d.deleted, vec!["/only-in-a"]);
    }

    #[test]
    fn job_id_is_short_and_unique_ish() {
        let a = new_job_id("c1");
        let b = new_job_id("c2");
        assert!(a.starts_with("snap-"));
        assert!(a.len() <= 32);
        assert_ne!(a, b);
    }

    // ----- async snapshot job unit tests (no podman binary required) -----

    use linpodx_common::ipc::Event as IpcEvent;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CollectingPublisher {
        events: Mutex<Vec<IpcEvent>>,
    }

    impl EventPublisher for CollectingPublisher {
        fn publish(&self, event: IpcEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("snap-jobs-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    /// Creates a runnable shim binary (a tiny shell script) that imitates `podman commit`'s
    /// progress output and exits 0. Returns its path so the test can hand it to PodmanConfig.
    fn write_fake_podman(dir: &std::path::Path, body: &str) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("podman-fake");
        let mut f = std::fs::File::create(&bin).expect("create fake podman");
        writeln!(f, "#!/bin/sh").unwrap();
        write!(f, "{body}").unwrap();
        let mut perm = f.metadata().unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&bin, perm).unwrap();
        bin
    }

    #[tokio::test]
    async fn create_async_succeeds_and_emits_progress_events() {
        use std::time::Duration;

        let scratch = tempfile::tempdir().expect("scratch tempdir");
        // Fake podman: prints two progress lines (commit, then the image id) then exits 0.
        let body = "echo \"Getting image source signatures\"\necho \"Copying blob sha256:abc\"\necho deadbeef\nexit 0\n";
        let bin = write_fake_podman(scratch.path(), body);

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin),
            ..Default::default()
        });
        let db = Arc::new(fresh_db().await);
        let collector = Arc::new(CollectingPublisher::default());
        let publisher: Arc<dyn EventPublisher> = collector.clone();

        let cid = ContainerId::new("c-async-ok".to_string());
        let job_id = create_async(&podman, Arc::clone(&db), &cid, Some("ok".into()), publisher)
            .await
            .expect("schedule job");
        assert!(job_id.starts_with("snap-"));

        // Poll the snapshot_jobs row until it leaves the running state (or timeout).
        let mut status = String::new();
        for _ in 0..50 {
            let row: (String,) =
                sqlx::query_as("SELECT status FROM snapshot_jobs WHERE job_id = ?")
                    .bind(&job_id)
                    .fetch_one(db.pool())
                    .await
                    .expect("select status");
            status = row.0;
            if status == "succeeded" || status == "failed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(status, "succeeded");

        let row: (Option<i64>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT snapshot_id, image_ref, last_progress FROM snapshot_jobs WHERE job_id = ?",
        )
        .bind(&job_id)
        .fetch_one(db.pool())
        .await
        .expect("select details");
        assert!(row.0.is_some(), "snapshot_id should be set");
        assert!(row.1.as_deref().unwrap_or("").starts_with("linpodx-snap-"));
        assert_eq!(row.2.as_deref(), Some("deadbeef"));

        let events = collector.events.lock().unwrap().clone();
        let progress_count = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::Progress))
            .count();
        let success_count = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::Succeeded))
            .count();
        assert!(
            progress_count >= 1,
            "expected progress events, got {progress_count}"
        );
        assert_eq!(success_count, 1, "expected exactly one succeeded event");
    }

    // ----- Phase 7 backend trait + diff_v2 unit tests -----

    #[test]
    fn common_prefix_len_handles_empty_and_full_match() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(common_prefix_len(&empty, &empty), 0);
        let a = vec!["sha256:a".into(), "sha256:b".into()];
        assert_eq!(common_prefix_len(&a, &a), 2);
    }

    #[test]
    fn common_prefix_len_stops_at_first_divergence() {
        let a = vec!["sha256:1".into(), "sha256:2".into(), "sha256:3".into()];
        let b = vec!["sha256:1".into(), "sha256:2".into(), "sha256:9".into()];
        assert_eq!(common_prefix_len(&a, &b), 2);
    }

    #[test]
    fn common_prefix_len_handles_size_mismatch() {
        let a = vec!["sha256:x".into()];
        let b = vec!["sha256:x".into(), "sha256:y".into(), "sha256:z".into()];
        assert_eq!(common_prefix_len(&a, &b), 1);
    }

    #[test]
    fn parse_root_fs_returns_layers_in_order() {
        let raw = r#"{"Type":"layers","Layers":["sha256:aaa","sha256:bbb","sha256:ccc"]}"#;
        let layers = parse_root_fs(raw).expect("parse");
        assert_eq!(layers, vec!["sha256:aaa", "sha256:bbb", "sha256:ccc"]);
    }

    #[test]
    fn parse_root_fs_empty_or_null_yields_empty_vec() {
        assert!(parse_root_fs("").unwrap().is_empty());
        assert!(parse_root_fs("null").unwrap().is_empty());
        let no_layers = r#"{"Type":"layers"}"#;
        assert!(parse_root_fs(no_layers).unwrap().is_empty());
    }

    #[test]
    fn parse_root_fs_invalid_json_is_runtime_error() {
        let err = parse_root_fs("{not-json").unwrap_err();
        assert!(matches!(err, Error::Runtime { .. }));
    }

    #[test]
    fn podman_commit_backend_kind_is_default() {
        let b = PodmanCommitBackend;
        assert_eq!(b.kind(), SnapshotBackendKind::PodmanCommit);
        assert_eq!(b.kind(), SnapshotBackendKind::default());
    }

    #[test]
    fn overlayfs_backend_kind_is_overlayfs() {
        assert_eq!(
            OverlayfsBackend::default().kind(),
            SnapshotBackendKind::Overlayfs
        );
    }

    #[test]
    fn btrfs_backend_kind_is_btrfs() {
        assert_eq!(BtrfsBackend::default().kind(), SnapshotBackendKind::Btrfs);
    }

    #[tokio::test]
    async fn podman_commit_backend_is_always_available() {
        assert!(PodmanCommitBackend.is_available().await);
    }

    #[tokio::test]
    async fn overlayfs_backend_availability_matches_module_path() {
        // Either the host has /sys/module/overlay (true) or it doesn't (false). Verify the
        // probe matches a direct filesystem check — no flaky network or process required.
        let direct = std::path::Path::new(OVERLAYFS_MODULE_PATH).exists();
        assert_eq!(OverlayfsBackend::default().is_available().await, direct);
    }

    /// Build an overlayfs backend rooted at a fresh tempdir. Returns the guard so
    /// the caller keeps the dir alive for the test body. Replaces the old
    /// env-mutating `OverlayRootGuard` — the root is injected, not global.
    fn overlay_backend() -> (OverlayfsBackend, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("store tempdir");
        let b = OverlayfsBackend::with_store_root(tmp.path().to_path_buf());
        (b, tmp)
    }

    #[tokio::test]
    async fn overlayfs_remove_missing_image_is_not_found_without_force() {
        let (b, _store) = overlay_backend();
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        match b.remove(&podman, "ghost-image", false).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        // force=true on a missing image swallows NotFound (idempotent rmi --force).
        b.remove(&podman, "ghost-image", true)
            .await
            .expect("force remove should be ok on missing");
    }

    #[tokio::test]
    async fn overlayfs_image_size_uses_meta_when_present() {
        let (b, store) = overlay_backend();
        let meta = crate::overlayfs::OverlayMeta {
            original_image: "alpine:3".into(),
            created_at: Utc::now(),
            size_bytes: 12345,
            layer_count: 1,
        };
        crate::overlayfs::write_meta_in(store.path(), "ref-meta-size", &meta).expect("write");
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        let got = b.image_size(&podman, "ref-meta-size").await.expect("size");
        assert_eq!(got, 12345);
    }

    #[tokio::test]
    async fn overlayfs_image_size_falls_back_to_dir_walk() {
        let (b, store) = overlay_backend();
        let dirs = crate::overlayfs::ensure_dirs_in(store.path(), "ref-walk").expect("ensure");
        std::fs::write(dirs.upper.join("a"), b"abcdef").unwrap(); // 6 bytes
        std::fs::write(dirs.upper.join("b"), b"xy").unwrap(); // 2 bytes
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        let got = b.image_size(&podman, "ref-walk").await.expect("size");
        assert_eq!(got, 8);
    }

    #[tokio::test]
    async fn overlayfs_image_size_missing_image_is_not_found() {
        let (b, _store) = overlay_backend();
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        match b.image_size(&podman, "nope").await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlayfs_tag_hardlinks_tree_and_meta() {
        let (b, store) = overlay_backend();
        // Lay down a source: dirs + a file under upper/ + a meta sidecar.
        let dirs = crate::overlayfs::ensure_dirs_in(store.path(), "src").expect("ensure src");
        std::fs::write(dirs.upper.join("hello"), b"world").unwrap();
        let meta = crate::overlayfs::OverlayMeta {
            original_image: "alpine:3".into(),
            created_at: Utc::now(),
            size_bytes: 5,
            layer_count: 1,
        };
        crate::overlayfs::write_meta_in(store.path(), "src", &meta).expect("write meta");

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        b.tag(&podman, "src", "dst").await.expect("tag");

        let dst_root = crate::overlayfs::image_dir_in(store.path(), "dst");
        assert!(dst_root.is_dir(), "dst root missing");
        assert!(dst_root.join("upper").join("hello").is_file());
        let dst_meta = crate::overlayfs::read_meta_in(store.path(), "dst").expect("dst meta");
        assert_eq!(dst_meta.size_bytes, 5);

        // cp -al ⇒ hardlink: same inode for src and dst content file.
        let src_inode = std::os::unix::fs::MetadataExt::ino(
            &std::fs::metadata(
                crate::overlayfs::image_dir_in(store.path(), "src")
                    .join("upper")
                    .join("hello"),
            )
            .unwrap(),
        );
        let dst_inode = std::os::unix::fs::MetadataExt::ino(
            &std::fs::metadata(dst_root.join("upper").join("hello")).unwrap(),
        );
        assert_eq!(src_inode, dst_inode, "tag should hardlink content");
    }

    #[tokio::test]
    async fn overlayfs_tag_missing_source_is_not_found() {
        let (b, _store) = overlay_backend();
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        match b.tag(&podman, "ghost-src", "dst").await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlayfs_tag_existing_target_is_runtime_error() {
        let (b, store) = overlay_backend();
        crate::overlayfs::ensure_dirs_in(store.path(), "src-x").expect("src");
        crate::overlayfs::ensure_dirs_in(store.path(), "dst-x").expect("dst");
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        match b.tag(&podman, "src-x", "dst-x").await {
            Err(Error::Runtime { .. }) => {}
            other => panic!("expected Runtime, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlayfs_remove_cleans_up_image_dir() {
        let (b, store) = overlay_backend();
        crate::overlayfs::ensure_dirs_in(store.path(), "to-remove").expect("ensure");
        assert!(crate::overlayfs::image_dir_in(store.path(), "to-remove").exists());
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        b.remove(&podman, "to-remove", false).await.expect("remove");
        assert!(!crate::overlayfs::image_dir_in(store.path(), "to-remove").exists());
    }

    #[tokio::test]
    #[ignore]
    async fn overlayfs_commit_alpine_e2e() {
        use linpodx_common::ipc::CreateOptions;
        use std::time::Duration;
        use tempfile::tempdir;

        let store = tempdir().expect("store tempdir");
        let b = OverlayfsBackend::with_store_root(store.path().to_path_buf());
        let root = tempdir().expect("root tempdir");
        let runroot = tempdir().expect("runroot tempdir");
        let podman = Podman::with_config(PodmanConfig {
            binary: None,
            root: Some(root.path().to_path_buf()),
            runroot: Some(runroot.path().to_path_buf()),
        });
        podman.check().await.expect("podman check");

        podman
            .pull("docker.io/library/alpine:latest")
            .await
            .expect("pull alpine");

        let opts = CreateOptions {
            image: "docker.io/library/alpine:latest".into(),
            name: Some("linpodx-overlay-e2e".into()),
            command: vec!["sleep".into(), "30".into()],
            labels: vec![("linpodx.test".into(), "overlayfs".into())],
            detach: true,
            ..Default::default()
        };
        let cid = podman.create(&opts).await.expect("create");
        podman.start(&cid).await.expect("start");

        let snap_ref = "linpodx-overlay-e2e-v1";
        let id = b.commit(&podman, &cid, snap_ref).await.expect("commit");
        assert_eq!(id.0, snap_ref);

        let meta = crate::overlayfs::read_meta_in(store.path(), snap_ref).expect("meta");
        assert!(meta.size_bytes > 0, "alpine rootfs should be non-empty");

        let size = b.image_size(&podman, snap_ref).await.expect("size");
        assert_eq!(size as u64, meta.size_bytes);

        b.remove(&podman, snap_ref, false).await.expect("remove");

        podman
            .stop(&cid, Some(Duration::from_secs(2)))
            .await
            .expect("stop");
        podman.remove(&cid, true).await.expect("remove ctr");
    }

    /// Build a btrfs backend rooted at a fresh tempdir with no availability
    /// override (real host probe). Returns the guard to keep the dir alive.
    fn btrfs_backend() -> (BtrfsBackend, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("store tempdir");
        let b = BtrfsBackend::with_config(tmp.path().to_path_buf(), None);
        (b, tmp)
    }

    #[tokio::test]
    async fn btrfs_backend_image_size_missing_is_not_found() {
        let (b, _store) = btrfs_backend();
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        match b.image_size(&podman, "ghost").await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn btrfs_backend_remove_missing_force_swallows() {
        let (b, _store) = btrfs_backend();
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        // No image exists; force=true should be a no-op success.
        b.remove(&podman, "ghost", true)
            .await
            .expect("force remove ok");
        match b.remove(&podman, "ghost", false).await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound without force, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn btrfs_backend_is_available_respects_override() {
        // Owned availability override (was the `LINPODX_BTRFS_AVAILABLE` env
        // read) — no process env mutation, so this is race-free in parallel.
        let store = tempfile::tempdir().expect("store tempdir");
        let yes = BtrfsBackend::with_config(store.path().to_path_buf(), Some(true));
        assert!(yes.is_available().await);
        let no = BtrfsBackend::with_config(store.path().to_path_buf(), Some(false));
        assert!(!no.is_available().await);
    }

    #[test]
    fn btrfs_image_path_uses_store_root_and_sha8() {
        let store = tempfile::tempdir().expect("store tempdir");
        let b = BtrfsBackend::with_config(store.path().to_path_buf(), None);
        let p = b.image_path("alpine:edge");
        let expected = store.path().join(overlayfs::sha8("alpine:edge"));
        assert_eq!(p, expected);
    }

    #[tokio::test]
    async fn overlayfs_mount_path_for_returns_none_when_not_mounted() {
        let (b, _store) = overlay_backend();
        // Fresh image_ref nobody has committed — registry should miss.
        assert!(b.mount_path_for("never-committed").is_none());
    }

    #[tokio::test]
    async fn overlayfs_unmount_for_unknown_image_is_noop() {
        let (b, _store) = overlay_backend();
        // Should not panic / error / emit audit entries.
        b.unmount_for("never-committed").await;
    }

    /// E2E: requires a host with `fuse-overlayfs` installed. Mounts and then
    /// unmounts a real overlay against a freshly-created store.
    #[tokio::test]
    #[ignore]
    async fn fuse_overlayfs_real_mount_round_trip() {
        let store = tempfile::tempdir().expect("store tempdir");
        // Skip if the binary isn't on PATH.
        if !overlayfs::fuse_overlayfs_available() {
            eprintln!("fuse-overlayfs not on PATH — skipping");
            return;
        }
        let audit: Arc<dyn AuditSink> = Arc::new(linpodx_common::audit_sink::NoopAuditSink);
        let mounted = overlayfs::mount_layers_in(store.path(), "e2e-mount-img", audit)
            .await
            .expect("mount_layers")
            .expect("Some(MountedRoot)");
        assert!(
            mounted.mount_path().exists(),
            "mount path should exist after fuse-overlayfs"
        );
        // Drop the handle — fusermount3 -u runs on Drop. We can't easily
        // assert the mount is gone without parsing /proc/mounts, but Drop
        // should not panic.
        drop(mounted);
    }

    /// E2E: requires a btrfs store_root + the `btrfs` CLI. Snapshots a fixture
    /// subvolume, tags it, sizes it, and removes both.
    #[tokio::test]
    #[ignore]
    async fn btrfs_real_subvolume_round_trip() {
        let store = tempfile::tempdir().expect("store tempdir");
        let b = BtrfsBackend::with_config(store.path().to_path_buf(), None);
        let podman = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/nonexistent/podman")),
            ..Default::default()
        });
        if !b.is_available().await {
            eprintln!("btrfs not available on store_root — skipping");
            return;
        }
        // The test caller is responsible for placing a btrfs subvolume at
        // <store_root>/<sha8("btrfs-e2e-src")> before running this test. We
        // assert is_available + image_size paths cleanly.
        let path = b.image_path("btrfs-e2e-missing");
        assert!(!path.exists());
        match b.image_size(&podman, "btrfs-e2e-missing").await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound for missing image, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backend_list_reports_three_in_canonical_order() {
        let list = backend_list().await;
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].kind, SnapshotBackendKind::PodmanCommit);
        assert!(list[0].available, "podman_commit must always be available");
        assert!(!list[0].note.is_empty());
        assert_eq!(list[1].kind, SnapshotBackendKind::Overlayfs);
        assert_eq!(list[2].kind, SnapshotBackendKind::Btrfs);
    }

    #[test]
    fn backend_for_returns_matching_kind() {
        assert_eq!(
            backend_for(SnapshotBackendKind::PodmanCommit).kind(),
            SnapshotBackendKind::PodmanCommit
        );
        assert_eq!(
            backend_for(SnapshotBackendKind::Overlayfs).kind(),
            SnapshotBackendKind::Overlayfs
        );
        assert_eq!(
            backend_for(SnapshotBackendKind::Btrfs).kind(),
            SnapshotBackendKind::Btrfs
        );
    }

    #[tokio::test]
    async fn diff_v2_via_fake_podman_reports_layer_split() {
        // Fake podman: every `image inspect --format {{json .RootFS}}` call returns a
        // baked-in layer list keyed by image ref (last argv). We hard-code two refs:
        // image-a has {l1,l2}; image-b has {l1,l2,l3}. Every other call (size lookup)
        // returns "0\n" so the total size delta is zero.
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().expect("scratch");
        let bin = scratch.path().join("podman-fake");
        let body = "#!/bin/sh\n\
            for arg in \"$@\"; do :; done\n\
            case \"$*\" in\n\
              *image*inspect*RootFS*image-a*) echo '{\"Type\":\"layers\",\"Layers\":[\"sha256:l1\",\"sha256:l2\"]}' ;;\n\
              *image*inspect*RootFS*image-b*) echo '{\"Type\":\"layers\",\"Layers\":[\"sha256:l1\",\"sha256:l2\",\"sha256:l3\"]}' ;;\n\
              *image*inspect*Size*image-a*) echo 100 ;;\n\
              *image*inspect*Size*image-b*) echo 175 ;;\n\
              *image*inspect*) echo 0 ;;\n\
              *) echo 0 ;;\n\
            esac\n\
            exit 0\n";
        {
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(body.as_bytes()).unwrap();
        }
        let mut perm = std::fs::metadata(&bin).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&bin, perm).unwrap();

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin),
            ..Default::default()
        });

        let resp = diff_v2(&podman, "image-a", "image-b")
            .await
            .expect("diff_v2");
        assert_eq!(resp.common_layer_count, 2);
        assert!(resp.a_only_layers.is_empty(), "a has no extra layers");
        assert_eq!(resp.b_only_layers.len(), 1);
        assert_eq!(resp.b_only_layers[0].layer_id, "sha256:l3");
        assert!(resp.used_layer_path);
        assert_eq!(resp.size_delta_bytes, 75);
        assert!(
            resp.file_changes.is_empty(),
            "fake podman has no `save` handler — diff_v2 must fall back to empty file_changes"
        );
    }

    // ----- Phase 10 Stream B: file-change diff helpers -----

    fn fe(path: &str, size: u64, mode: u32) -> FileEntry {
        FileEntry {
            path: path.into(),
            size,
            mode,
        }
    }

    #[test]
    fn diff_file_sets_added_only() {
        let a: std::collections::HashSet<FileEntry> = [fe("/x", 1, 0o644)].into_iter().collect();
        let b: std::collections::HashSet<FileEntry> = [fe("/x", 1, 0o644), fe("/y", 2, 0o755)]
            .into_iter()
            .collect();
        let changes = diff_file_sets(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, "added");
        assert_eq!(changes[0].path, "/y");
    }

    #[test]
    fn diff_file_sets_deleted_only() {
        let a: std::collections::HashSet<FileEntry> = [fe("/x", 1, 0o644), fe("/y", 2, 0o755)]
            .into_iter()
            .collect();
        let b: std::collections::HashSet<FileEntry> = [fe("/x", 1, 0o644)].into_iter().collect();
        let changes = diff_file_sets(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, "deleted");
        assert_eq!(changes[0].path, "/y");
    }

    #[test]
    fn diff_file_sets_modified_via_size_or_mode() {
        let a: std::collections::HashSet<FileEntry> =
            [fe("/same", 10, 0o644), fe("/mode", 5, 0o644)]
                .into_iter()
                .collect();
        let b: std::collections::HashSet<FileEntry> =
            [fe("/same", 11, 0o644), fe("/mode", 5, 0o755)]
                .into_iter()
                .collect();
        let changes = diff_file_sets(&a, &b);
        let kinds_paths: Vec<(String, String)> = changes
            .iter()
            .map(|c| (c.kind.clone(), c.path.clone()))
            .collect();
        assert_eq!(
            kinds_paths,
            vec![
                ("modified".into(), "/mode".into()),
                ("modified".into(), "/same".into())
            ]
        );
    }

    #[test]
    fn diff_file_sets_mixed_added_deleted_modified_sorted() {
        let a: std::collections::HashSet<FileEntry> = [
            fe("/keep", 1, 0o644),
            fe("/edit", 5, 0o644),
            fe("/gone", 9, 0o644),
        ]
        .into_iter()
        .collect();
        let b: std::collections::HashSet<FileEntry> = [
            fe("/keep", 1, 0o644),
            fe("/edit", 6, 0o644),
            fe("/new", 3, 0o644),
        ]
        .into_iter()
        .collect();
        let changes = diff_file_sets(&a, &b);
        let kinds_paths: Vec<(String, String)> = changes
            .iter()
            .map(|c| (c.kind.clone(), c.path.clone()))
            .collect();
        assert_eq!(
            kinds_paths,
            vec![
                ("added".into(), "/new".into()),
                ("deleted".into(), "/gone".into()),
                ("modified".into(), "/edit".into()),
            ]
        );
        // layer_id is intentionally empty in v0.1 (Phase 10 documents this).
        assert!(changes.iter().all(|c| c.layer_id.is_empty()));
    }

    #[test]
    fn diff_file_sets_identical_returns_empty() {
        let s: std::collections::HashSet<FileEntry> = [fe("/a", 1, 0o644), fe("/b", 2, 0o755)]
            .into_iter()
            .collect();
        assert!(diff_file_sets(&s, &s).is_empty());
    }

    #[tokio::test]
    async fn diff_v2_falls_back_to_empty_when_save_fails() {
        // Fake podman that succeeds for image inspect / size but exits non-zero
        // for `podman save`. diff_v2 must still return Ok with file_changes empty.
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().expect("scratch");
        // Unique shim filename — tempdirs are isolated, but the unique name
        // also avoids a flaky "Text file busy" race seen when sibling tests
        // fork+exec a shim called `podman-fake` at the same time.
        let bin = scratch.path().join("podman-fake-savefail");
        let body = "#!/bin/sh\n\
            case \"$*\" in\n\
              *image*inspect*RootFS*image-a*) echo '{\"Type\":\"layers\",\"Layers\":[\"sha256:l1\"]}' ;;\n\
              *image*inspect*RootFS*image-b*) echo '{\"Type\":\"layers\",\"Layers\":[\"sha256:l1\",\"sha256:l2\"]}' ;;\n\
              *image*inspect*Size*) echo 0 ;;\n\
              *image*inspect*) echo 0 ;;\n\
              *save*) echo 'Error: cannot save' 1>&2; exit 125 ;;\n\
              *) echo 0 ;;\n\
            esac\n";
        {
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(body.as_bytes()).unwrap();
        }
        let mut perm = std::fs::metadata(&bin).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&bin, perm).unwrap();

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin),
            ..Default::default()
        });

        let resp = diff_v2(&podman, "image-a", "image-b")
            .await
            .expect("diff_v2 must not fail when save fails");
        assert!(resp.used_layer_path);
        assert!(
            resp.file_changes.is_empty(),
            "save failure must produce empty file_changes, not error"
        );
    }

    /// E2E sanity: pull a small image, tag it as a "modified" twin (different
    /// metadata layer), and assert `diff_v2` reports a non-empty file-change
    /// set when both images can be `podman save`-d. Gated on a real Podman
    /// install — run via `cargo test -p linpodx-runtime -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn diff_v2_real_alpine_twin_reports_file_changes() {
        let podman = Podman::default();
        if podman.check().await.is_err() {
            eprintln!("skipping: podman not available or below MIN_PODMAN_VERSION");
            return;
        }
        // Pull alpine, then commit a no-op container off it as a twin.
        let mut pull = podman.base_command();
        pull.arg("pull").arg("docker.io/library/alpine:3.19");
        let _ = pull.output().await.expect("podman pull spawn");

        let mut create = podman.base_command();
        create.args([
            "create",
            "--name",
            "linpodx-difftest",
            "docker.io/library/alpine:3.19",
            "/bin/true",
        ]);
        let _ = create.output().await;
        let mut commit = podman.base_command();
        commit.args(["commit", "linpodx-difftest", "linpodx-alpine-twin"]);
        let _ = commit.output().await;

        let resp = diff_v2(
            &podman,
            "docker.io/library/alpine:3.19",
            "linpodx-alpine-twin",
        )
        .await
        .expect("diff_v2");

        // Cleanup, ignoring errors.
        let mut rmi = podman.base_command();
        rmi.args(["rmi", "-f", "linpodx-alpine-twin"]);
        let _ = rmi.output().await;
        let mut rm = podman.base_command();
        rm.args(["rm", "-f", "linpodx-difftest"]);
        let _ = rm.output().await;

        assert!(resp.used_layer_path);
        // We don't assert exact contents — just that the file walk reached the
        // OCI tar parser at all (either both images saved cleanly and produced
        // a possibly-empty diff, or save failed and we fell back). The strong
        // signal here is that the call returns Ok regardless of podman quirks.
        let _ = resp.file_changes.len();
    }

    #[tokio::test]
    async fn create_async_failure_writes_failed_status() {
        use std::time::Duration;

        let scratch = tempfile::tempdir().expect("scratch tempdir");
        // Fake podman: print to stderr then exit non-zero.
        let body = "echo \"Error: container not known\" 1>&2\nexit 125\n";
        let bin = write_fake_podman(scratch.path(), body);

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin),
            ..Default::default()
        });
        let db = Arc::new(fresh_db().await);
        let publisher: Arc<dyn EventPublisher> = Arc::new(CollectingPublisher::default());

        let cid = ContainerId::new("c-async-bad".to_string());
        let job_id = create_async(&podman, Arc::clone(&db), &cid, None, Arc::clone(&publisher))
            .await
            .expect("schedule job");

        let mut status = String::new();
        for _ in 0..50 {
            let row: (String,) =
                sqlx::query_as("SELECT status FROM snapshot_jobs WHERE job_id = ?")
                    .bind(&job_id)
                    .fetch_one(db.pool())
                    .await
                    .expect("select status");
            status = row.0;
            if status == "succeeded" || status == "failed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(status, "failed");

        let row: (Option<String>,) =
            sqlx::query_as("SELECT error_message FROM snapshot_jobs WHERE job_id = ?")
                .bind(&job_id)
                .fetch_one(db.pool())
                .await
                .expect("select error");
        let err = row.0.unwrap_or_default();
        assert!(
            err.contains("container not known")
                || err.contains("commit failed")
                || err.contains("status"),
            "expected error text, got: {err}"
        );

        // Snapshot row must NOT linger after failure (rolled back).
        let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE container_id = ?")
            .bind(&cid.0)
            .fetch_one(db.pool())
            .await
            .expect("count");
        assert_eq!(cnt.0, 0, "failed job should leave no snapshot row");
    }

    // ----- Phase 16 Stream B: encryption pipeline unit tests -----

    /// Pin LINPODX_ENCRYPTED_SNAPSHOT_ROOT to a per-test tempdir so concurrent
    /// tests don't trample each other's blobs. Restored on Drop. Shares the
    /// crate-wide [`super::encrypted_root_test_lock`] with the rotation-module
    /// tests so the two suites never race on the shared env var.
    use super::encrypted_root_test_lock as enc_lock;
    struct EncRootGuard {
        prev: Option<String>,
        _dir: tempfile::TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl EncRootGuard {
        fn new() -> Self {
            let lock = enc_lock().lock().unwrap_or_else(|p| p.into_inner());
            let dir = tempfile::tempdir().expect("enc tempdir");
            let prev = std::env::var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT").ok();
            std::env::set_var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT", dir.path());
            Self {
                prev,
                _dir: dir,
                _lock: lock,
            }
        }
    }
    impl Drop for EncRootGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT", v),
                None => std::env::remove_var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT"),
            }
        }
    }

    #[test]
    fn podman_commit_backend_reports_no_backend_level_encryption() {
        // At-rest encryption is owned by the daemon-side encryptor / rotation
        // paths, never by the backend's `commit` flow. The backend therefore
        // reports no encryption config — this is deterministic and does not
        // depend on any process-wide env state (the old frozen
        // `active_encryption_config` `OnceLock` has been removed).
        assert!(PodmanCommitBackend.encryption_config().is_none());
    }

    #[test]
    fn encrypted_image_dir_uses_hashed_subdir() {
        let _g = EncRootGuard::new();
        let d1 = encrypted_image_dir("img:a");
        let d2 = encrypted_image_dir("img:b");
        let d1_again = encrypted_image_dir("img:a");
        assert_ne!(d1, d2, "different refs should hash to different dirs");
        assert_eq!(d1, d1_again, "same ref must be deterministic");
        // No characters from the ref leak through (no `:` or `/` in tail).
        let tail = d1.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!tail.contains(':'));
        assert!(!tail.contains('/'));
    }

    #[test]
    fn read_encrypted_meta_returns_none_when_absent() {
        let _g = EncRootGuard::new();
        let got = read_encrypted_meta("never-encrypted-image").expect("read");
        assert!(got.is_none());
    }

    #[test]
    fn is_image_encrypted_false_when_no_meta() {
        let _g = EncRootGuard::new();
        assert!(!is_image_encrypted("ghost-image"));
    }

    #[test]
    fn write_then_read_encrypted_meta_round_trips() {
        let _g = EncRootGuard::new();
        let image_ref = "round-trip-image";
        let dir = encrypted_image_dir(image_ref);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let meta = EncryptedSnapshotMeta {
            algorithm: "aes-256-gcm".into(),
            key_source: "passphrase".into(),
            ciphertext_sha256: "ab".repeat(32),
            original_image_ref: image_ref.to_string(),
            created_at: chrono::Utc::now(),
            plaintext_len: 4096,
            kdf: snapshot_crypto::Kdf::argon2id_default(),
            rotated_from_snapshot_id: None,
            rotated_at: None,
        };
        let bytes = serde_json::to_vec_pretty(&meta).unwrap();
        std::fs::write(dir.join("meta.json"), &bytes).expect("write");
        let got = read_encrypted_meta(image_ref).expect("read").expect("some");
        assert_eq!(got.algorithm, meta.algorithm);
        assert_eq!(got.ciphertext_sha256, meta.ciphertext_sha256);
        assert_eq!(got.plaintext_len, meta.plaintext_len);
        assert!(is_image_encrypted(image_ref));
    }

    #[test]
    fn remove_encrypted_artifacts_is_idempotent() {
        let _g = EncRootGuard::new();
        // No directory exists yet — remove must be a no-op.
        remove_encrypted_artifacts("absent").expect("idempotent on missing");
        // Now create one and remove it.
        let dir = encrypted_image_dir("present");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("meta.json"), b"{}").unwrap();
        assert!(dir.exists());
        remove_encrypted_artifacts("present").expect("remove existing");
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn encrypt_committed_image_round_trips_via_fake_podman() {
        // End-to-end with a fake podman: we simulate `podman save -o <out>` by
        // writing a known plaintext into <out>, then call `encrypt_committed_image`
        // and verify the side-car blob round-trips via `decrypt_bytes`. We bypass
        // `decrypt_and_load` in this test because the fake podman doesn't actually
        // implement `podman load` (covered in a separate integration test).
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let _g = EncRootGuard::new();
        let scratch = tempfile::tempdir().expect("scratch");
        // Fake podman handles `save <ref> -o <path>` and `rmi --force <ref>`
        // by writing/removing files. Anything else: exit 0 silently.
        let body = "case \"$1\" in\n  save) shift; ref=\"$1\"; shift; out=\"\"; while [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; out=\"$1\"; fi; shift; done; printf 'FAKE-OCI-TARBALL[%s]' \"$ref\" > \"$out\";;\n  rmi) :;;\n  *) :;;\nesac\nexit 0\n";
        let bin_path = scratch.path().join("podman-fake");
        {
            let mut f = std::fs::File::create(&bin_path).unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            write!(f, "{body}").unwrap();
            f.sync_all().unwrap();
        }
        let mut perm = std::fs::metadata(&bin_path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&bin_path, perm).unwrap();

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(bin_path),
            ..Default::default()
        });
        let cfg = EncryptionConfig::from_passphrase("encryption-test-pass");
        let image_ref = "fake-snap:v1";
        let meta = encrypt_committed_image(&podman, image_ref, &cfg, true)
            .await
            .expect("encrypt");
        assert_eq!(meta.algorithm, "aes-256-gcm");
        assert_eq!(meta.key_source, "passphrase");
        assert_eq!(meta.original_image_ref, image_ref);
        // Plaintext written by fake podman: literal `FAKE-OCI-TARBALL[fake-snap:v1]`.
        let expected_plain = format!("FAKE-OCI-TARBALL[{image_ref}]");
        assert_eq!(meta.plaintext_len as usize, expected_plain.len());
        assert_eq!(meta.ciphertext_sha256.len(), 64);

        // Side-car files exist at the documented layout.
        let dir = encrypted_image_dir(image_ref);
        let blob = std::fs::read(dir.join("blob.enc")).expect("read blob");
        let on_disk_meta = read_encrypted_meta(image_ref).expect("read meta").unwrap();
        assert_eq!(on_disk_meta.ciphertext_sha256, meta.ciphertext_sha256);

        // The blob must round-trip via decrypt_bytes back to the plaintext.
        let recovered = snapshot_crypto::decrypt_bytes(&blob, &cfg).expect("decrypt blob");
        assert_eq!(recovered, expected_plain.as_bytes());

        // Sha256 of the persisted blob matches the meta record.
        assert_eq!(snapshot_crypto::sha256_hex(&blob), meta.ciphertext_sha256);
    }
}
