//! `linpodx image(s) <...>` — image CRUD, pull progress streaming, push, and
//! multi-arch manifest management.
//!
//! The existing `Cmd::Images(ImagesCmd)` variant in `main.rs` carries the
//! singular `image` name as a `clap` *visible alias*. The two surfaces share
//! a single dispatch path — there is no parallel handler — so `linpodx image
//! ls` and `linpodx images ls` behave identically.
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{
    print_image_list, print_image_manifest_create, print_image_manifest_push, print_image_push,
    print_inspect, OutputFormat,
};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{
    responses, EventKind, EventTopic, ImageIdParams, ImageListParams, ImageManifestCreateParams,
    ImageManifestPushParams, ImagePullJobParams, ImagePullParams, ImagePushParams,
    ImageRemoveParams, ImageTagParams, Method, SubscribeParams,
};
use linpodx_common::state::ImageInspect;
use linpodx_common::state::ImageSummary;
use linpodx_common::types::ImageId;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum ImagesCmd {
    /// List images.
    Ls {
        /// Show all images including intermediate layers.
        #[arg(short = 'a', long)]
        all: bool,
        /// Only show dangling images.
        #[arg(long)]
        dangling: bool,
    },
    /// Pull an image from a registry.
    Pull {
        /// Stream pull progress lines as they arrive (Phase 11). Without this flag the
        /// CLI blocks on the synchronous `image_pull` IPC and prints only the final id.
        #[arg(long)]
        progress: bool,
        /// Image reference (e.g. `docker.io/library/alpine:latest`).
        reference: String,
    },
    /// Remove an image.
    Rm {
        /// Force remove.
        #[arg(short = 'f', long)]
        force: bool,
        id: String,
    },
    /// Show low-level image info as pretty JSON.
    Inspect { id: String },
    /// Tag an image with an additional name.
    Tag {
        /// Source image (id or `repo:tag`).
        source: String,
        /// Target tag (e.g. `myrepo/app:1.0`).
        target: String,
    },
    /// Push an image to a registry.
    Push {
        /// Image reference (e.g. `registry.example.com/me/app:1.0`).
        reference: String,
        /// Optional registry override; the destination becomes `<registry>/<reference>`.
        #[arg(long)]
        registry: Option<String>,
        /// Optional base64(`user:password`) auth blob. When omitted podman falls
        /// back to its configured auth file.
        #[arg(long)]
        auth: Option<String>,
        /// Path to a directory containing `cert.pem`, `key.pem`, and `ca.pem`
        /// for mTLS to a private registry. Mapped to `podman push --cert-dir`.
        /// Must exist and be a directory at parse time.
        #[arg(long, value_parser = parse_existing_dir)]
        cert_dir: Option<PathBuf>,
    },
    /// Manage multi-arch manifest lists.
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum ManifestCmd {
    /// Create a local manifest list from one or more references.
    Create {
        /// Local manifest list name (e.g. `myapp:1.0`).
        target: String,
        /// References to add. Pass `--ref` once per reference.
        #[arg(long = "ref", required = true)]
        refs: Vec<String>,
    },
    /// Add a single reference to an existing manifest list.
    Add {
        /// Manifest list name (e.g. `myapp:1.0`).
        target: String,
        /// Reference to add (e.g. `myrepo/app:1.0-arm64`).
        reference: String,
    },
    /// Push a manifest list to a registry.
    Push {
        /// Manifest list name (e.g. `myapp:1.0`).
        manifest: String,
        /// Optional registry override; the destination becomes `<registry>/<manifest>`.
        #[arg(long)]
        registry: Option<String>,
        /// Optional base64(`user:password`) auth blob.
        #[arg(long)]
        auth: Option<String>,
    },
}

/// clap value parser: accept a path only when it exists and is a directory.
/// Used for `--cert-dir` on `image push` so that operators get a clean parse-time
/// error instead of a podman error mid-push.
fn parse_existing_dir(s: &str) -> std::result::Result<PathBuf, String> {
    let p = PathBuf::from(s);
    if !p.exists() {
        return Err(format!("path does not exist: {s}"));
    }
    if !p.is_dir() {
        return Err(format!("path is not a directory: {s}"));
    }
    Ok(p)
}

pub(crate) async fn handle_images(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: ImagesCmd,
) -> Result<()> {
    match cmd {
        ImagesCmd::Ls { all, dangling } => {
            let images: Vec<ImageSummary> = client
                .call(Method::ImageList(ImageListParams {
                    all,
                    dangling: if dangling { Some(true) } else { None },
                }))
                .await?;
            print_image_list(&images, fmt)?;
        }
        ImagesCmd::Pull {
            progress,
            reference,
        } => {
            if progress {
                handle_image_pull_progress(client, reference).await?;
            } else {
                let id: ImageId = client
                    .call(Method::ImagePull(ImagePullParams { reference }))
                    .await?;
                println!("{id}");
            }
        }
        ImagesCmd::Rm { force, id } => {
            let id = ImageId::from(id);
            let _: serde_json::Value = client
                .call(Method::ImageRemove(ImageRemoveParams {
                    id: id.clone(),
                    force,
                }))
                .await?;
            println!("{id}");
        }
        ImagesCmd::Inspect { id } => {
            let id = ImageId::from(id);
            let inspect: ImageInspect = client
                .call(Method::ImageInspect(ImageIdParams { id }))
                .await?;
            print_inspect(&inspect, fmt)?;
        }
        ImagesCmd::Tag { source, target } => {
            let source = ImageId::from(source);
            let _: serde_json::Value = client
                .call(Method::ImageTag(ImageTagParams {
                    source: source.clone(),
                    target,
                }))
                .await?;
            println!("{source}");
        }
        ImagesCmd::Push {
            reference,
            registry,
            auth,
            cert_dir,
        } => {
            let resp: responses::ImagePushResponse = client
                .call(Method::ImagePush(ImagePushParams {
                    reference,
                    registry,
                    auth,
                    cert_dir,
                }))
                .await?;
            print_image_push(&resp, fmt)?;
        }
        ImagesCmd::Manifest { cmd } => match cmd {
            ManifestCmd::Create { target, refs } => {
                let resp: responses::ImageManifestCreateResponse = client
                    .call(Method::ImageManifestCreate(ImageManifestCreateParams {
                        target,
                        refs,
                    }))
                    .await?;
                print_image_manifest_create(&resp, fmt)?;
            }
            ManifestCmd::Add { target, reference } => {
                // Reuse manifest_create with a single ref — it's idempotent on
                // the target manifest, so this becomes a single `manifest add`.
                let resp: responses::ImageManifestCreateResponse = client
                    .call(Method::ImageManifestCreate(ImageManifestCreateParams {
                        target,
                        refs: vec![reference],
                    }))
                    .await?;
                print_image_manifest_create(&resp, fmt)?;
            }
            ManifestCmd::Push {
                manifest,
                registry,
                auth,
            } => {
                let resp: responses::ImageManifestPushResponse = client
                    .call(Method::ImageManifestPush(ImageManifestPushParams {
                        manifest,
                        registry,
                        auth,
                    }))
                    .await?;
                print_image_manifest_push(&resp, fmt)?;
            }
        },
    }
    Ok(())
}

/// Phase 11 — `linpodx images pull --progress <ref>`. Subscribes to Image topic and
/// prints `EventKind::Progress` lines until the daemon reports `Succeeded` or `Failed`.
async fn handle_image_pull_progress(client: &mut Client, reference: String) -> Result<()> {
    use linpodx_common::ipc::responses::{ImagePullJobResponse, SubscribeResponse};

    let _sub_ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: vec![EventTopic::Image],
        }))
        .await?;
    let job: ImagePullJobResponse = client
        .call(Method::ImagePullJob(ImagePullJobParams {
            reference: reference.clone(),
        }))
        .await?;
    eprintln!("pull job {} started for {}", job.job_id, reference);
    while let Some(event) = client.next_event().await? {
        if event.topic != EventTopic::Image || event.resource_id != job.job_id {
            continue;
        }
        match event.kind {
            EventKind::Progress => {
                let msg = event
                    .details
                    .get("message")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default();
                println!("{msg}");
            }
            EventKind::Succeeded => {
                eprintln!("pull job {} succeeded", job.job_id);
                return Ok(());
            }
            EventKind::Failed => {
                eprintln!("pull job {} failed", job.job_id);
                std::process::exit(1);
            }
            _ => {}
        }
    }
    eprintln!("daemon closed the event stream before pull job terminated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_image_push_with_registry_and_auth() {
        let cli = Cli::parse_from([
            "linpodx",
            "images",
            "push",
            "docker.io/me/app:1.0",
            "--registry",
            "registry.example.com",
            "--auth",
            "YWxpY2U6czNjcmV0",
        ]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Push {
                reference,
                registry,
                auth,
                cert_dir,
            }) => {
                assert_eq!(reference, "docker.io/me/app:1.0");
                assert_eq!(registry.as_deref(), Some("registry.example.com"));
                assert_eq!(auth.as_deref(), Some("YWxpY2U6czNjcmV0"));
                assert!(cert_dir.is_none());
            }
            other => panic!("expected Images Push subcommand, got {other:?}"),
        }
    }

    // ---- Phase 14: image push --cert-dir ----

    #[test]
    fn parse_image_push_with_cert_dir_pointing_at_existing_directory() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let cli = Cli::parse_from([
            "linpodx",
            "images",
            "push",
            "registry.internal/me/app:1.0",
            "--cert-dir",
            tmp.path().to_str().expect("utf-8 tempdir path"),
        ]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Push {
                reference,
                registry,
                auth,
                cert_dir,
            }) => {
                assert_eq!(reference, "registry.internal/me/app:1.0");
                assert!(registry.is_none());
                assert!(auth.is_none());
                assert_eq!(cert_dir.as_deref(), Some(tmp.path()));
            }
            other => panic!("expected Images Push subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_push_rejects_nonexistent_cert_dir() {
        // Pick a path that's overwhelmingly unlikely to exist.
        let bogus = "/nonexistent/linpodx/cert-dir/should/not/exist/xyz123";
        let result = Cli::try_parse_from([
            "linpodx",
            "images",
            "push",
            "me/app:1.0",
            "--cert-dir",
            bogus,
        ]);
        assert!(result.is_err(), "expected clap parse error for missing dir");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not exist") || err.contains("not a directory"),
            "error should mention path existence problem: {err}"
        );
    }

    #[test]
    fn parse_image_push_rejects_cert_dir_that_is_a_file() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let file_path = tmp.path().join("not-a-dir.pem");
        std::fs::write(&file_path, b"dummy").expect("write tmp file");
        let result = Cli::try_parse_from([
            "linpodx",
            "images",
            "push",
            "me/app:1.0",
            "--cert-dir",
            file_path.to_str().expect("utf-8 path"),
        ]);
        assert!(
            result.is_err(),
            "expected clap parse error for non-dir path"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not a directory"),
            "error should report 'not a directory': {err}"
        );
    }

    #[test]
    fn parse_image_manifest_create_collects_repeated_refs() {
        let cli = Cli::parse_from([
            "linpodx",
            "images",
            "manifest",
            "create",
            "myapp:1.0",
            "--ref",
            "myrepo/app:1.0-amd64",
            "--ref",
            "myrepo/app:1.0-arm64",
        ]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Manifest {
                cmd: ManifestCmd::Create { target, refs },
            }) => {
                assert_eq!(target, "myapp:1.0");
                assert_eq!(
                    refs,
                    vec![
                        "myrepo/app:1.0-amd64".to_string(),
                        "myrepo/app:1.0-arm64".to_string(),
                    ]
                );
            }
            other => panic!("expected Manifest Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_manifest_push_minimum_args() {
        let cli = Cli::parse_from(["linpodx", "images", "manifest", "push", "myapp:1.0"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Manifest {
                cmd:
                    ManifestCmd::Push {
                        manifest,
                        registry,
                        auth,
                    },
            }) => {
                assert_eq!(manifest, "myapp:1.0");
                assert!(registry.is_none());
                assert!(auth.is_none());
            }
            other => panic!("expected Manifest Push subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_manifest_create_requires_at_least_one_ref() {
        let result = Cli::try_parse_from(["linpodx", "images", "manifest", "create", "myapp:1.0"]);
        assert!(result.is_err(), "manifest create with no --ref should fail");
    }

    #[test]
    fn parse_image_pull_with_progress_flag() {
        let cli = Cli::parse_from(["linpodx", "images", "pull", "--progress", "alpine:latest"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Pull {
                progress,
                reference,
            }) => {
                assert!(progress);
                assert_eq!(reference, "alpine:latest");
            }
            other => panic!("expected Images Pull subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_pull_default_no_progress() {
        let cli = Cli::parse_from(["linpodx", "images", "pull", "alpine:latest"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Pull { progress, .. }) => assert!(!progress),
            other => panic!("expected Images Pull subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_singular_alias_resolves_to_images_subcommand() {
        // `image ls` should reach the same `ImagesCmd::Ls` value as `images ls`.
        let cli = Cli::parse_from(["linpodx", "image", "ls"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Ls { all, dangling }) => {
                assert!(!all);
                assert!(!dangling);
            }
            other => panic!("expected Images::Ls, got {other:?}"),
        }
    }
}
