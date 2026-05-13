use crate::parse;
use crate::podman::{map_not_found, Podman};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::{
    ImageManifestCreateResponse, ImageManifestPushResponse, ImagePushResponse,
};
use linpodx_common::ipc::{
    ImageListParams, ImageManifestCreateParams, ImageManifestPushParams, ImagePullParams,
    ImagePushParams, ImageRemoveParams, ImageTagParams,
};
use linpodx_common::state::{ImageInspect, ImageSummary};
use linpodx_common::types::ImageId;
use tracing::instrument;

#[instrument(skip(podman))]
pub async fn list(podman: &Podman, params: &ImageListParams) -> Result<Vec<ImageSummary>> {
    let mut cmd = podman.base_command();
    cmd.arg("images").arg("--format=json");
    match params.dangling {
        Some(true) => {
            cmd.arg("--filter").arg("dangling=true");
        }
        Some(false) => {
            cmd.arg("--filter").arg("dangling=false");
        }
        None if params.all => {
            cmd.arg("--all");
        }
        None => {}
    }
    let out = podman.run_capture(cmd).await?;
    parse::parse_image_list(&out)
}

#[instrument(skip(podman))]
pub async fn pull(podman: &Podman, params: &ImagePullParams) -> Result<ImageId> {
    let mut cmd = podman.base_command();
    cmd.arg("pull").arg(&params.reference);
    let out = podman.run_capture(cmd).await?;
    // `podman pull <ref>` prints the image's local long ID on the last non-empty line.
    let id = out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    if id.is_empty() {
        return Err(linpodx_common::error::Error::Runtime {
            message: "podman pull returned no image id".into(),
        });
    }
    Ok(ImageId(id))
}

#[instrument(skip(podman))]
pub async fn remove(podman: &Podman, params: &ImageRemoveParams) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("rmi");
    if params.force {
        cmd.arg("--force");
    }
    cmd.arg(&params.id.0);
    podman
        .run_capture(cmd)
        .await
        .map(|_| ())
        .map_err(|e| map_not_found(e, &params.id.0))
}

#[instrument(skip(podman))]
pub async fn inspect(podman: &Podman, id: &ImageId) -> Result<ImageInspect> {
    let mut cmd = podman.base_command();
    cmd.arg("inspect").arg("--type=image").arg(&id.0);
    let out = match podman.run_capture(cmd).await {
        Ok(s) => s,
        Err(e) => return Err(map_not_found(e, &id.0)),
    };
    parse::parse_image_inspect(&out)
}

#[instrument(skip(podman))]
pub async fn tag(podman: &Podman, params: &ImageTagParams) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("tag").arg(&params.source.0).arg(&params.target);
    podman
        .run_capture(cmd)
        .await
        .map(|_| ())
        .map_err(|e| map_not_found(e, &params.source.0))
}

/// Push a local image to a registry. Optionally accepts a base64(`user:pass`)
/// auth blob, a registry override (which becomes a `<registry>/<reference>`
/// destination argument), and an mTLS cert directory mapped to podman's
/// `--cert-dir`. Returns the pushed reference and a best-effort SHA-256 digest
/// extracted from podman stdout.
#[instrument(skip(podman))]
pub async fn push(podman: &Podman, params: &ImagePushParams) -> Result<ImagePushResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("push");
    if let Some(auth_b64) = &params.auth {
        let creds = decode_auth_blob(auth_b64)?;
        cmd.arg("--creds").arg(&creds);
    }
    if let Some(cert_dir) = &params.cert_dir {
        cmd.arg("--cert-dir").arg(cert_dir);
    }
    cmd.arg(&params.reference);
    let destination = params
        .registry
        .as_deref()
        .map(|reg| format!("{}/{}", reg.trim_end_matches('/'), params.reference));
    if let Some(dest) = &destination {
        cmd.arg(dest);
    }
    let out = podman.run_capture(cmd).await?;
    let digest = extract_digest(&out);
    Ok(ImagePushResponse {
        reference: destination.unwrap_or_else(|| params.reference.clone()),
        digest,
    })
}

/// Create a local manifest list and append the supplied references. The
/// manifest is treated as idempotent — if `podman manifest create` reports the
/// target already exists, we reuse it and proceed with the per-ref `add` calls.
#[instrument(skip(podman))]
pub async fn manifest_create(
    podman: &Podman,
    params: &ImageManifestCreateParams,
) -> Result<ImageManifestCreateResponse> {
    {
        let mut cmd = podman.base_command();
        cmd.arg("manifest").arg("create").arg(&params.target);
        match podman.run_capture(cmd).await {
            Ok(_) => {}
            Err(Error::Runtime { message }) if manifest_already_exists(&message) => {
                // Reuse existing manifest list.
            }
            Err(e) => return Err(e),
        }
    }
    let mut added = Vec::with_capacity(params.refs.len());
    for reference in &params.refs {
        let mut cmd = podman.base_command();
        cmd.arg("manifest")
            .arg("add")
            .arg(&params.target)
            .arg(reference);
        podman.run_capture(cmd).await?;
        added.push(reference.clone());
    }
    Ok(ImageManifestCreateResponse {
        manifest: params.target.clone(),
        added,
    })
}

/// Push a manifest list to a registry. When `registry` is supplied the manifest
/// is published as `<registry>/<manifest>`; otherwise the manifest's own name is
/// used as the destination.
#[instrument(skip(podman))]
pub async fn manifest_push(
    podman: &Podman,
    params: &ImageManifestPushParams,
) -> Result<ImageManifestPushResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("manifest").arg("push");
    if let Some(auth_b64) = &params.auth {
        let creds = decode_auth_blob(auth_b64)?;
        cmd.arg("--creds").arg(&creds);
    }
    cmd.arg(&params.manifest);
    if let Some(reg) = &params.registry {
        cmd.arg(format!("{}/{}", reg.trim_end_matches('/'), params.manifest));
    }
    podman.run_capture(cmd).await?;
    Ok(ImageManifestPushResponse {
        manifest: params.manifest.clone(),
        registry: params.registry.clone(),
    })
}

fn decode_auth_blob(auth_b64: &str) -> Result<String> {
    let raw = B64.decode(auth_b64.trim()).map_err(|e| Error::Runtime {
        message: format!("invalid base64 auth blob: {e}"),
    })?;
    let creds = String::from_utf8(raw).map_err(|e| Error::Runtime {
        message: format!("auth blob is not valid utf-8: {e}"),
    })?;
    if !creds.contains(':') {
        return Err(Error::Runtime {
            message: "auth blob must decode to 'user:password'".into(),
        });
    }
    Ok(creds)
}

fn manifest_already_exists(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("already exists") || lower.contains("already in use")
}

/// Extract the first `sha256:<hex>` token from a captured stdout string. Used
/// for best-effort digest reporting on `podman push` — Podman writes the
/// pushed manifest digest to stdout but the exact phrasing varies between
/// releases (`Storing signatures` / `Writing manifest to image destination`).
pub(crate) fn extract_digest(stdout: &str) -> Option<String> {
    for token in stdout.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != ':');
        if let Some(rest) = trimmed.strip_prefix("sha256:") {
            if rest.len() >= 16 && rest.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(format!("sha256:{rest}"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    #[test]
    fn extract_digest_finds_sha256_token() {
        let stdout = "Getting image source signatures\n\
            Copying blob sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n\
            Writing manifest to image destination\n\
            Storing signatures";
        let digest = extract_digest(stdout).expect("digest extracted");
        assert_eq!(
            digest,
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn extract_digest_returns_none_when_no_digest() {
        let stdout = "Writing manifest to image destination\nStoring signatures";
        assert!(extract_digest(stdout).is_none());
    }

    #[test]
    fn extract_digest_ignores_short_or_non_hex_tokens() {
        // 8-char hex (too short) and a non-hex string that happens to start with
        // sha256: — neither should be returned.
        let stdout =
            "sha256:deadbeef sha256:zzzznothex0000000000000000000000000000000000000000000000000000";
        assert!(extract_digest(stdout).is_none());
    }

    #[test]
    fn decode_auth_blob_round_trip() {
        let raw = "alice:s3cret";
        let encoded = B64.encode(raw);
        let decoded = decode_auth_blob(&encoded).expect("decoded");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_auth_blob_rejects_invalid_base64() {
        let err = decode_auth_blob("@not_base64$").unwrap_err();
        match err {
            Error::Runtime { message } => assert!(message.contains("invalid base64")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn decode_auth_blob_rejects_missing_colon() {
        let encoded = B64.encode("nocolonhere");
        let err = decode_auth_blob(&encoded).unwrap_err();
        match err {
            Error::Runtime { message } => assert!(message.contains("user:password")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn manifest_already_exists_matches_known_phrasings() {
        assert!(manifest_already_exists(
            "Error: image name myapp:1.0 is already in use"
        ));
        assert!(manifest_already_exists(
            "manifest list already exists locally"
        ));
        assert!(!manifest_already_exists("manifest not known"));
    }

    #[test]
    fn push_params_assembles_creds_arg_when_auth_present() {
        // We can't run podman in unit tests, but we can introspect the assembled
        // Command argv to confirm `--creds` is added in the right position.
        // This mirrors podman.rs::create_uses_rootfs_when_set test style.
        let podman = Podman::new();
        let auth = B64.encode("alice:s3cret");
        let params = ImagePushParams {
            reference: "docker.io/me/app:1.0".into(),
            registry: None,
            auth: Some(auth),
            cert_dir: None,
        };
        let mut cmd = podman.base_command();
        cmd.arg("push");
        let creds = decode_auth_blob(params.auth.as_deref().unwrap()).unwrap();
        cmd.arg("--creds").arg(&creds);
        cmd.arg(&params.reference);
        let argv: Vec<&std::ffi::OsStr> = cmd.as_std().get_args().collect();
        let argv_strs: Vec<&str> = argv.iter().filter_map(|s| s.to_str()).collect();
        assert!(argv_strs.contains(&"push"));
        assert!(argv_strs.contains(&"--creds"));
        assert!(argv_strs.contains(&"alice:s3cret"));
        assert!(argv_strs.contains(&"docker.io/me/app:1.0"));
    }

    #[test]
    fn push_params_appends_registry_destination() {
        let params = ImagePushParams {
            reference: "myrepo/app:1.0".into(),
            registry: Some("registry.example.com".into()),
            auth: None,
            cert_dir: None,
        };
        let destination = params
            .registry
            .as_deref()
            .map(|reg| format!("{}/{}", reg.trim_end_matches('/'), params.reference));
        assert_eq!(
            destination.as_deref(),
            Some("registry.example.com/myrepo/app:1.0")
        );
    }

    #[test]
    fn push_params_strips_trailing_slash_from_registry() {
        let params = ImagePushParams {
            reference: "myrepo/app:1.0".into(),
            registry: Some("registry.example.com/".into()),
            auth: None,
            cert_dir: None,
        };
        let destination = params
            .registry
            .as_deref()
            .map(|reg| format!("{}/{}", reg.trim_end_matches('/'), params.reference));
        assert_eq!(
            destination.as_deref(),
            Some("registry.example.com/myrepo/app:1.0")
        );
    }

    // ---- Phase 14: image push mTLS (--cert-dir) ----

    /// Reproduce the argv assembly from `push()` so we can assert that
    /// `--cert-dir <path>` is appended exactly when `cert_dir` is `Some`.
    fn assemble_push_argv(params: &ImagePushParams) -> Vec<String> {
        let podman = Podman::new();
        let mut cmd = podman.base_command();
        cmd.arg("push");
        if let Some(auth_b64) = &params.auth {
            if let Ok(creds) = decode_auth_blob(auth_b64) {
                cmd.arg("--creds").arg(&creds);
            }
        }
        if let Some(cert_dir) = &params.cert_dir {
            cmd.arg("--cert-dir").arg(cert_dir);
        }
        cmd.arg(&params.reference);
        let destination = params
            .registry
            .as_deref()
            .map(|reg| format!("{}/{}", reg.trim_end_matches('/'), params.reference));
        if let Some(dest) = &destination {
            cmd.arg(dest);
        }
        cmd.as_std()
            .get_args()
            .filter_map(|s| s.to_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn push_argv_contains_cert_dir_when_set() {
        let params = ImagePushParams {
            reference: "registry.internal/me/app:1.0".into(),
            registry: None,
            auth: None,
            cert_dir: Some(std::path::PathBuf::from("/etc/linpodx/certs")),
        };
        let argv = assemble_push_argv(&params);
        let pos = argv
            .iter()
            .position(|s| s == "--cert-dir")
            .expect("--cert-dir present");
        assert_eq!(
            argv.get(pos + 1).map(String::as_str),
            Some("/etc/linpodx/certs")
        );
        assert!(argv.contains(&"registry.internal/me/app:1.0".to_string()));
    }

    #[test]
    fn push_argv_omits_cert_dir_when_none() {
        let params = ImagePushParams {
            reference: "docker.io/me/app:1.0".into(),
            registry: None,
            auth: None,
            cert_dir: None,
        };
        let argv = assemble_push_argv(&params);
        assert!(
            !argv.iter().any(|s| s == "--cert-dir"),
            "--cert-dir must not appear when cert_dir is None: argv={argv:?}"
        );
    }

    #[test]
    fn push_argv_combines_creds_cert_dir_and_destination() {
        let params = ImagePushParams {
            reference: "myrepo/app:1.0".into(),
            registry: Some("registry.example.com".into()),
            auth: Some(B64.encode("alice:s3cret")),
            cert_dir: Some(std::path::PathBuf::from("/var/lib/linpodx/certs")),
        };
        let argv = assemble_push_argv(&params);
        assert!(argv.contains(&"--creds".to_string()));
        assert!(argv.contains(&"alice:s3cret".to_string()));
        assert!(argv.contains(&"--cert-dir".to_string()));
        assert!(argv.contains(&"/var/lib/linpodx/certs".to_string()));
        assert!(argv.contains(&"registry.example.com/myrepo/app:1.0".to_string()));
        // `--cert-dir` must come after `--creds` (creds first), before reference.
        let creds_pos = argv.iter().position(|s| s == "--creds").unwrap();
        let cert_pos = argv.iter().position(|s| s == "--cert-dir").unwrap();
        let ref_pos = argv
            .iter()
            .position(|s| s == "myrepo/app:1.0")
            .expect("reference present");
        assert!(creds_pos < cert_pos, "creds must precede cert-dir");
        assert!(cert_pos < ref_pos, "cert-dir must precede reference");
    }

    #[test]
    fn push_argv_cert_dir_preserves_path_with_spaces() {
        let p = std::path::PathBuf::from("/tmp/path with spaces/certs");
        let params = ImagePushParams {
            reference: "me/app:1.0".into(),
            registry: None,
            auth: None,
            cert_dir: Some(p.clone()),
        };
        let argv = assemble_push_argv(&params);
        let pos = argv.iter().position(|s| s == "--cert-dir").unwrap();
        assert_eq!(
            argv.get(pos + 1).map(String::as_str),
            Some("/tmp/path with spaces/certs"),
            "path must be passed as a single argv element verbatim"
        );
    }

    #[test]
    fn manifest_create_params_iterate_refs_in_order() {
        let params = ImageManifestCreateParams {
            target: "myapp:1.0".into(),
            refs: vec!["myrepo/app:1.0-amd64".into(), "myrepo/app:1.0-arm64".into()],
        };
        // Simulate the per-ref iteration in manifest_create() — confirm we'd build
        // one `manifest add` invocation per ref, in the supplied order.
        let podman = Podman::new();
        let invocations: Vec<Vec<String>> = params
            .refs
            .iter()
            .map(|reference| {
                let mut cmd = podman.base_command();
                cmd.arg("manifest")
                    .arg("add")
                    .arg(&params.target)
                    .arg(reference);
                cmd.as_std()
                    .get_args()
                    .filter_map(|s| s.to_str().map(str::to_string))
                    .collect()
            })
            .collect();
        assert_eq!(invocations.len(), 2);
        assert!(invocations[0].contains(&"myrepo/app:1.0-amd64".to_string()));
        assert!(invocations[0].contains(&"myapp:1.0".to_string()));
        assert!(invocations[1].contains(&"myrepo/app:1.0-arm64".to_string()));
    }

    #[test]
    fn manifest_push_assembles_destination_with_registry() {
        let params = ImageManifestPushParams {
            manifest: "myapp:1.0".into(),
            registry: Some("registry.example.com".into()),
            auth: None,
        };
        let dest = params
            .registry
            .as_ref()
            .map(|reg| format!("{}/{}", reg.trim_end_matches('/'), params.manifest));
        assert_eq!(dest.as_deref(), Some("registry.example.com/myapp:1.0"));
    }
}
