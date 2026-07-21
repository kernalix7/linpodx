//! Snapshot-domain dispatch handlers: create/list/inspect/rollback/remove/
//! prune, async jobs, tree diff (+ OCI-layer `diff_v2`), pluggable backends,
//! at-rest encryption status, and Phase 17 key rotation / re-encryption.

use super::*;

impl Dispatcher {
    pub(crate) async fn snapshot_create(
        &self,
        p: linpodx_common::ipc::SnapshotCreateParams,
    ) -> Result<serde_json::Value> {
        let cid = ContainerId::new(p.container_id);
        let summary = self.snapshot.create(&self.podman, &cid, p.label).await?;
        Ok(serde_json::to_value(responses::SnapshotCreateResponse {
            id: summary.id,
            image_ref: summary.image_ref,
        })?)
    }

    pub(crate) async fn snapshot_list(
        &self,
        p: linpodx_common::ipc::SnapshotListParams,
    ) -> Result<serde_json::Value> {
        let summaries = self.snapshot.list(p.container_id.as_deref()).await?;
        Ok(serde_json::to_value(summaries)?)
    }

    pub(crate) async fn snapshot_inspect(
        &self,
        p: linpodx_common::ipc::SnapshotIdParams,
    ) -> Result<serde_json::Value> {
        let summary = self.snapshot.inspect(p.id).await?;
        Ok(serde_json::to_value(summary)?)
    }

    pub(crate) async fn snapshot_rollback(
        &self,
        p: linpodx_common::ipc::SnapshotRollbackParams,
    ) -> Result<serde_json::Value> {
        let resp = self
            .snapshot
            .rollback(&self.podman, p.id, p.new_name, p.keep_original)
            .await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn snapshot_remove(
        &self,
        p: linpodx_common::ipc::SnapshotRemoveParams,
    ) -> Result<serde_json::Value> {
        self.snapshot.remove(&self.podman, p.id, p.force).await?;
        Ok(serde_json::Value::Null)
    }

    pub(crate) async fn snapshot_prune(
        &self,
        p: linpodx_common::ipc::SnapshotPruneParams,
    ) -> Result<serde_json::Value> {
        let removed = self
            .snapshot
            .prune(
                &self.podman,
                p.container_id.as_deref(),
                p.keep_recent.unwrap_or(0),
            )
            .await?;
        Ok(serde_json::to_value(responses::SnapshotPruneResponse {
            removed,
        })?)
    }

    pub(crate) async fn snapshot_job_create(
        &self,
        p: linpodx_common::ipc::SnapshotJobCreateParams,
    ) -> Result<serde_json::Value> {
        let cid = ContainerId::new(p.container_id);
        let db = self.snapshot.database().clone();
        let publisher = self.snapshot.publisher();
        let job_id =
            runtime_snapshot::create_async(&self.podman, db, &cid, p.label, publisher).await?;
        Ok(serde_json::to_value(
            responses::SnapshotJobCreateResponse {
                job_id,
                status: "pending".into(),
            },
        )?)
    }

    pub(crate) async fn snapshot_job_status(
        &self,
        p: linpodx_common::ipc::SnapshotJobStatusParams,
    ) -> Result<serde_json::Value> {
        let db = self.snapshot.database();
        let snap = runtime_snapshot::query_job_status(db, &p.job_id).await?;
        let resp = responses::SnapshotJobStatusResponse {
            job_id: snap.job_id,
            container_id: snap.container_id,
            label: snap.label,
            status: snap.status,
            snapshot_id: snap.snapshot_id,
            image_ref: snap.image_ref,
            last_progress: snap.last_progress,
            error_message: snap.error_message,
            started_at: snap.started_at,
            ended_at: snap.ended_at,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn snapshot_diff(
        &self,
        p: linpodx_common::ipc::SnapshotDiffParams,
    ) -> Result<serde_json::Value> {
        let resp = self.snapshot.diff(&self.podman, p.id_a, p.id_b).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn snapshot_branch(
        &self,
        p: linpodx_common::ipc::SnapshotBranchParams,
    ) -> Result<serde_json::Value> {
        let summary = self
            .snapshot
            .create_branch(&self.podman, p.parent_id, p.label, p.fork)
            .await?;
        Ok(serde_json::to_value(summary)?)
    }

    pub(crate) async fn snapshot_diff_v2(
        &self,
        p: linpodx_common::ipc::SnapshotDiffV2Params,
    ) -> Result<serde_json::Value> {
        let resp = self.snapshot.diff_v2(&self.podman, p.id_a, p.id_b).await?;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn snapshot_backend_list(&self) -> Result<serde_json::Value> {
        let resp = self.snapshot.backend_list().await;
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn snapshot_encryption_status(
        &self,
        p: linpodx_common::ipc::SnapshotIdParams,
    ) -> Result<serde_json::Value> {
        // Phase 16 Stream B — at-rest encryption status. Read the snapshot
        // row to learn its image_ref, then prefer the on-disk side-car
        // produced by `runtime_snapshot::encrypt_committed_image` (source
        // of truth). Fall back to the DB columns when no side-car exists
        // — this lets daemons that pre-record encryption metadata at
        // commit time still answer authoritatively.
        let db = self.snapshot.database();
        type EncRow = (String, i64, Option<String>, Option<String>, Option<String>);
        let row: Option<EncRow> = sqlx::query_as(
            "SELECT image_ref, COALESCE(encrypted, 0), algorithm, key_source, \
             ciphertext_sha256 FROM snapshots WHERE id = ?",
        )
        .bind(p.id)
        .fetch_optional(db.pool())
        .await
        .map_err(Error::Sqlx)?;
        let (image_ref, db_encrypted, db_algo, db_source, db_sha) =
            row.ok_or_else(|| Error::NotFound(format!("snapshot id {}", p.id)))?;
        let resp = match runtime_snapshot::read_encrypted_meta(&image_ref)? {
            Some(meta) => responses::SnapshotEncryptionStatusResponse {
                snapshot_id: p.id,
                encrypted: true,
                algorithm: Some(meta.algorithm),
                key_source: Some(meta.key_source),
                ciphertext_sha256: Some(meta.ciphertext_sha256),
            },
            None => responses::SnapshotEncryptionStatusResponse {
                snapshot_id: p.id,
                encrypted: db_encrypted != 0,
                algorithm: db_algo,
                key_source: db_source,
                ciphertext_sha256: db_sha,
            },
        };
        Ok(serde_json::to_value(resp)?)
    }

    // ----- Phase 17 Stream A — snapshot key rotation / re-encryption.
    // The old key comes from the daemon's startup env (the snapshot was
    // encrypted under it); the new key is supplied in the IPC params via
    // the `SnapshotKeySource` enum.
    pub(crate) async fn snapshot_key_rotate(
        &self,
        p: linpodx_common::ipc::SnapshotKeyRotateParams,
    ) -> Result<serde_json::Value> {
        let old_cfg = resolve_old_snapshot_cfg()?;
        let new_cfg = resolve_new_snapshot_cfg(p.new_key.clone())?;
        let outcome = linpodx_runtime::rotate_snapshot_key(
            self.snapshot.database(),
            p.snapshot_id,
            &old_cfg,
            &new_cfg,
        )
        .await?;
        self.audit
            .record(
                AuditSinkKind::SnapshotKeyRotated,
                None,
                None,
                serde_json::json!({
                    "snapshot_id": outcome.snapshot_id,
                    "image_ref": outcome.image_ref,
                    "algorithm": outcome.algorithm,
                    "kdf": outcome.kdf,
                    "ciphertext_sha256": outcome.ciphertext_sha256,
                    "rotated_at": outcome.rotated_at,
                }),
            )
            .await;
        let resp = responses::SnapshotKeyRotateResponse {
            snapshot_id: outcome.snapshot_id,
            rotated: true,
            algorithm: outcome.algorithm,
            kdf: outcome.kdf,
            ciphertext_sha256: outcome.ciphertext_sha256,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn snapshot_re_encrypt_all(
        &self,
        p: linpodx_common::ipc::SnapshotReEncryptAllParams,
    ) -> Result<serde_json::Value> {
        let old_cfg = resolve_old_snapshot_cfg()?;
        let new_cfg = resolve_new_snapshot_cfg(p.new_key.clone())?;
        let outcome =
            linpodx_runtime::re_encrypt_all(self.snapshot.database(), &old_cfg, &new_cfg).await?;
        self.audit
            .record(
                AuditSinkKind::SnapshotReEncryptCompleted,
                None,
                None,
                serde_json::json!({
                    "total_seen": outcome.total_seen,
                    "re_encrypted": outcome.re_encrypted,
                    "skipped": outcome.skipped,
                    "failed": outcome.failed,
                }),
            )
            .await;
        let resp = responses::SnapshotReEncryptAllResponse {
            total_seen: outcome.total_seen,
            re_encrypted: outcome.re_encrypted,
            skipped: outcome.skipped,
            failed: outcome.failed,
        };
        Ok(serde_json::to_value(resp)?)
    }
}
