//! `linpodx snapshot <...>` — container snapshots (Phase 2B), async jobs
//! (Phase 2E), layer-aware diff (Phase 7), branching, and at-rest encryption
//! key management (Phase 16/17).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{
    print_snapshot_backend_list, print_snapshot_diff, print_snapshot_diff_v2,
    print_snapshot_job_status, print_snapshot_list, OutputFormat,
};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{
    Method, SnapshotBranchParams, SnapshotCreateParams, SnapshotDiffParams, SnapshotDiffV2Params,
    SnapshotIdParams, SnapshotJobCreateParams, SnapshotJobStatusParams, SnapshotKeyRotateParams,
    SnapshotKeySource, SnapshotListParams, SnapshotPruneParams, SnapshotReEncryptAllParams,
    SnapshotRemoveParams, SnapshotRollbackParams,
};

#[derive(Subcommand, Debug)]
pub(crate) enum SnapshotCmd {
    /// Snapshot a container into an OCI image (`linpodx-snap-<id>`).
    Create {
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Container id or name.
        container: String,
    },
    /// List snapshots, optionally filtered by container.
    List {
        /// Filter by container id or name.
        #[arg(long)]
        container: Option<String>,
    },
    /// Show one snapshot row as pretty JSON.
    Inspect { id: i64 },
    /// Rebuild a container from a snapshot. Removes the original by default.
    Rollback {
        /// Name for the new container. Default: `<original>-restored`.
        #[arg(long)]
        new_name: Option<String>,
        /// Keep the original container instead of removing it.
        #[arg(long)]
        keep_original: bool,
        id: i64,
    },
    /// Remove a snapshot (image + DB row).
    Rm {
        /// Force remove even if other refs exist.
        #[arg(short = 'f', long)]
        force: bool,
        id: i64,
    },
    /// Prune snapshots, optionally keeping the N newest per scope.
    Prune {
        /// Limit to a single container.
        #[arg(long)]
        container: Option<String>,
        /// Keep this many newest snapshots. Default: 0 (delete all matching).
        #[arg(long)]
        keep_recent: Option<u32>,
    },
    /// Async snapshot jobs (Phase 2E) — non-blocking commit + Progress events.
    #[command(subcommand)]
    Job(SnapshotJobCmd),
    /// Show file-level diff between two snapshots (added / modified / deleted).
    /// Pass `--layers` to use the OCI layer-aware diff (Phase 7) instead of the
    /// classic `podman diff` set-difference.
    Diff {
        /// Use the layer-aware diff path (lists shared / a-only / b-only layers and
        /// per-layer file changes when available).
        #[arg(long)]
        layers: bool,
        /// Snapshot id "A" — the baseline.
        id_a: i64,
        /// Snapshot id "B" — the comparison.
        id_b: i64,
    },
    /// List the snapshot backends compiled into the daemon and their current
    /// availability on this host.
    BackendList,
    /// Branch an existing snapshot: tag its image with a fresh ref and link the new
    /// row to the parent. Both rows then share the same underlying image content unless
    /// `--fork` is passed, which runs a real `podman commit` from the parent's
    /// container so the new row owns its own image content (fork-on-write).
    Branch {
        /// Optional human-readable label for the new branch row.
        #[arg(long)]
        label: Option<String>,
        /// Materialise a new image via `podman commit` on the parent's container
        /// instead of just tagging. Requires the container to still be present.
        #[arg(long)]
        fork: bool,
        /// Parent snapshot id to branch from.
        parent_id: i64,
    },
    /// Phase 16 Stream B — show at-rest encryption metadata for a snapshot.
    /// Returns whether the snapshot's image was encrypted via the AES-256-GCM
    /// pipeline (LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE / LINPODX_SNAPSHOT_KEY)
    /// and surfaces the algorithm / key-source / ciphertext sha256 for audit.
    EncryptionStatus {
        /// Snapshot id (from `snapshot list`).
        id: i64,
    },
    /// Phase 17 Stream A — rotate the at-rest encryption key for a single
    /// snapshot. Decrypts the side-car blob under the daemon's current key
    /// and re-encrypts under the supplied passphrase or explicit base64 key.
    KeyRotate {
        /// Snapshot id to rotate (from `snapshot list`).
        id: i64,
        /// New passphrase (mixed through Argon2id by default). Mutually
        /// exclusive with `--new-key`.
        #[arg(long, conflicts_with = "new_key")]
        new_passphrase: Option<String>,
        /// Raw 32-byte base64 key. Mutually exclusive with `--new-passphrase`.
        #[arg(long, conflicts_with = "new_passphrase")]
        new_key: Option<String>,
    },
    /// Phase 17 Stream A — re-encrypt every snapshot in the DB under a new
    /// key. Skips never-encrypted snapshots and continues past per-row
    /// failures; the response reports total / re-encrypted / skipped / failed.
    ReEncryptAll {
        /// New passphrase (Argon2id by default). Mutually exclusive with
        /// `--new-key`.
        #[arg(long, conflicts_with = "new_key")]
        new_passphrase: Option<String>,
        /// Raw 32-byte base64 key. Mutually exclusive with `--new-passphrase`.
        #[arg(long, conflicts_with = "new_passphrase")]
        new_key: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum SnapshotJobCmd {
    /// Enqueue a snapshot job for a container; returns the job id immediately.
    Start {
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Container id or name.
        container: String,
    },
    /// Show the current state of a snapshot job (queued / running / succeeded / failed).
    Status { job_id: String },
}

pub(crate) async fn handle_snapshot(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: SnapshotCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        SnapshotBranchResponse, SnapshotCreateResponse, SnapshotDiffResponse,
        SnapshotJobCreateResponse, SnapshotJobStatusResponse, SnapshotListResponse,
        SnapshotPruneResponse, SnapshotRollbackResponse, SnapshotSummary,
    };
    match cmd {
        SnapshotCmd::Create { label, container } => {
            let resp: SnapshotCreateResponse = client
                .call(Method::SnapshotCreate(SnapshotCreateParams {
                    container_id: container,
                    label,
                }))
                .await?;
            println!("{}\t{}", resp.id, resp.image_ref);
        }
        SnapshotCmd::List { container } => {
            let snapshots: SnapshotListResponse = client
                .call(Method::SnapshotList(SnapshotListParams {
                    container_id: container,
                }))
                .await?;
            print_snapshot_list(&snapshots, fmt)?;
        }
        SnapshotCmd::Inspect { id } => {
            let summary: SnapshotSummary = client
                .call(Method::SnapshotInspect(SnapshotIdParams { id }))
                .await?;
            crate::output::print_inspect(&summary, fmt)?;
        }
        SnapshotCmd::Rollback {
            new_name,
            keep_original,
            id,
        } => {
            let resp: SnapshotRollbackResponse = client
                .call(Method::SnapshotRollback(SnapshotRollbackParams {
                    id,
                    new_name,
                    keep_original,
                }))
                .await?;
            println!("{}\t{}", resp.new_container_id, resp.new_container_name);
        }
        SnapshotCmd::Rm { force, id } => {
            let _: serde_json::Value = client
                .call(Method::SnapshotRemove(SnapshotRemoveParams { id, force }))
                .await?;
            println!("{id}");
        }
        SnapshotCmd::Prune {
            container,
            keep_recent,
        } => {
            let resp: SnapshotPruneResponse = client
                .call(Method::SnapshotPrune(SnapshotPruneParams {
                    container_id: container,
                    keep_recent,
                }))
                .await?;
            if resp.removed.is_empty() {
                println!("No snapshots to prune.");
            } else {
                println!("Removed {} snapshot(s):", resp.removed.len());
                for id in resp.removed {
                    println!("  {id}");
                }
            }
        }
        SnapshotCmd::Job(SnapshotJobCmd::Start { label, container }) => {
            let resp: SnapshotJobCreateResponse = client
                .call(Method::SnapshotJobCreate(SnapshotJobCreateParams {
                    container_id: container,
                    label,
                }))
                .await?;
            println!("{}\t{}", resp.job_id, resp.status);
        }
        SnapshotCmd::Job(SnapshotJobCmd::Status { job_id }) => {
            let resp: SnapshotJobStatusResponse = client
                .call(Method::SnapshotJobStatus(SnapshotJobStatusParams {
                    job_id,
                }))
                .await?;
            print_snapshot_job_status(&resp, fmt)?;
        }
        SnapshotCmd::Diff { layers, id_a, id_b } => {
            if layers {
                use linpodx_common::ipc::responses::SnapshotDiffV2Response;
                let resp: SnapshotDiffV2Response = client
                    .call(Method::SnapshotDiffV2(SnapshotDiffV2Params { id_a, id_b }))
                    .await?;
                print_snapshot_diff_v2(&resp, fmt)?;
            } else {
                let resp: SnapshotDiffResponse = client
                    .call(Method::SnapshotDiff(SnapshotDiffParams { id_a, id_b }))
                    .await?;
                print_snapshot_diff(&resp, fmt)?;
            }
        }
        SnapshotCmd::BackendList => {
            use linpodx_common::ipc::responses::SnapshotBackendListResponse;
            let resp: SnapshotBackendListResponse =
                client.call(Method::SnapshotBackendList).await?;
            print_snapshot_backend_list(&resp, fmt)?;
        }
        SnapshotCmd::Branch {
            label,
            fork,
            parent_id,
        } => {
            let resp: SnapshotBranchResponse = client
                .call(Method::SnapshotBranch(SnapshotBranchParams {
                    parent_id,
                    label,
                    fork,
                }))
                .await?;
            println!("{}\t{}", resp.id, resp.image_ref);
        }
        SnapshotCmd::EncryptionStatus { id } => {
            use linpodx_common::ipc::responses::SnapshotEncryptionStatusResponse;
            let resp: SnapshotEncryptionStatusResponse = client
                .call(Method::SnapshotEncryptionStatus(SnapshotIdParams { id }))
                .await?;
            match fmt {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                OutputFormat::Table => {
                    let dash = "-".to_string();
                    println!("snapshot_id      : {}", resp.snapshot_id);
                    println!("encrypted        : {}", resp.encrypted);
                    println!(
                        "algorithm        : {}",
                        resp.algorithm.as_ref().unwrap_or(&dash)
                    );
                    println!(
                        "key_source       : {}",
                        resp.key_source.as_ref().unwrap_or(&dash)
                    );
                    println!(
                        "ciphertext_sha256: {}",
                        resp.ciphertext_sha256.as_ref().unwrap_or(&dash)
                    );
                }
            }
        }
        SnapshotCmd::KeyRotate {
            id,
            new_passphrase,
            new_key,
        } => {
            use linpodx_common::ipc::responses::SnapshotKeyRotateResponse;
            let new_key_src = build_new_key_source(new_passphrase, new_key)?;
            let resp: SnapshotKeyRotateResponse = client
                .call(Method::SnapshotKeyRotate(SnapshotKeyRotateParams {
                    snapshot_id: id,
                    new_key: new_key_src,
                }))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("snapshot_id      : {}", resp.snapshot_id);
                    println!("rotated          : {}", resp.rotated);
                    println!("algorithm        : {}", resp.algorithm);
                    println!("kdf              : {}", resp.kdf);
                    println!("ciphertext_sha256: {}", resp.ciphertext_sha256);
                }
            }
        }
        SnapshotCmd::ReEncryptAll {
            new_passphrase,
            new_key,
        } => {
            use linpodx_common::ipc::responses::SnapshotReEncryptAllResponse;
            let new_key_src = build_new_key_source(new_passphrase, new_key)?;
            let resp: SnapshotReEncryptAllResponse = client
                .call(Method::SnapshotReEncryptAll(SnapshotReEncryptAllParams {
                    new_key: new_key_src,
                }))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("total_seen   : {}", resp.total_seen);
                    println!("re_encrypted : {}", resp.re_encrypted);
                    println!("skipped      : {}", resp.skipped);
                    println!("failed       : {}", resp.failed);
                }
            }
        }
    }
    Ok(())
}

/// Phase 17 Stream A — build a `SnapshotKeySource` from `--new-passphrase` /
/// `--new-key`. Exactly one must be supplied; clap's `conflicts_with`
/// guarantees mutual exclusion, this helper only rejects the empty case.
fn build_new_key_source(
    new_passphrase: Option<String>,
    new_key: Option<String>,
) -> Result<SnapshotKeySource> {
    match (new_passphrase, new_key) {
        (Some(p), None) => Ok(SnapshotKeySource::Passphrase { passphrase: p }),
        (None, Some(k)) => Ok(SnapshotKeySource::Explicit { key_b64: k }),
        (None, None) => Err(anyhow::anyhow!(
            "supply either --new-passphrase <p> or --new-key <base64>"
        )),
        (Some(_), Some(_)) => unreachable!("clap conflicts_with enforces mutual exclusion"),
    }
}
