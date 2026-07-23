use crate::parse;
use crate::podman::{map_not_found, Podman};
use linpodx_common::error::Result;
use linpodx_common::ipc::responses::VolumeInspectDetailResponse;
use linpodx_common::ipc::{VolumeCreateParams, VolumeRemoveParams};
use linpodx_common::state::{VolumeInspect, VolumeSummary};
use linpodx_common::types::VolumeId;
use tracing::instrument;

#[instrument(skip(podman))]
pub async fn list(podman: &Podman) -> Result<Vec<VolumeSummary>> {
    let mut cmd = podman.base_command();
    cmd.arg("volume").arg("ls").arg("--format=json");
    let out = podman.run_capture(cmd).await?;
    parse::parse_volume_list(&out)
}

#[instrument(skip(podman))]
pub async fn create(podman: &Podman, params: &VolumeCreateParams) -> Result<VolumeId> {
    let mut cmd = podman.base_command();
    cmd.arg("volume").arg("create");
    if let Some(driver) = &params.driver {
        cmd.arg("--driver").arg(driver);
    }
    for (k, v) in &params.labels {
        cmd.arg("--label").arg(format!("{k}={v}"));
    }
    for (k, v) in &params.options {
        cmd.arg("--opt").arg(format!("{k}={v}"));
    }
    if let Some(name) = &params.name {
        cmd.arg(name);
    }
    let out = podman.run_capture(cmd).await?;
    let name = out.trim().to_string();
    if name.is_empty() {
        return Err(linpodx_common::error::Error::Runtime {
            message: "podman volume create returned empty name".into(),
        });
    }
    Ok(VolumeId(name))
}

#[instrument(skip(podman))]
pub async fn remove(podman: &Podman, params: &VolumeRemoveParams) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("volume").arg("rm");
    if params.force {
        cmd.arg("--force");
    }
    cmd.arg(&params.name.0);
    podman
        .run_capture(cmd)
        .await
        .map(|_| ())
        .map_err(|e| map_not_found(e, &params.name.0))
}

#[instrument(skip(podman))]
pub async fn inspect(podman: &Podman, name: &VolumeId) -> Result<VolumeInspect> {
    let mut cmd = podman.base_command();
    cmd.arg("volume").arg("inspect").arg(&name.0);
    let out = match podman.run_capture(cmd).await {
        Ok(s) => s,
        Err(e) => return Err(map_not_found(e, &name.0)),
    };
    parse::parse_volume_inspect(&out)
}

/// Richer volume detail for `GET /api/v1/volumes/:name/inspect` — augments the
/// frozen [`inspect`] output with a best-effort size (from `podman system df
/// -v --format json`) and the list of container names currently mounting the
/// volume (from `podman ps -a --filter volume=<name> --format json`). Both
/// augmenting lookups are tolerant of missing/renamed fields across podman
/// versions and degrade to `None` / empty rather than failing the whole call.
#[instrument(skip(podman))]
pub async fn inspect_detail(
    podman: &Podman,
    name: &VolumeId,
) -> Result<VolumeInspectDetailResponse> {
    let base = inspect(podman, name).await?;

    let size_bytes = volume_size_bytes(podman, &name.0).await;
    let in_use_by = volume_in_use_by(podman, &name.0).await;

    Ok(VolumeInspectDetailResponse {
        name: base.name.0,
        mountpoint: base.mountpoint,
        driver: base.driver,
        created: Some(base.created.to_rfc3339()),
        size_bytes,
        in_use_by,
    })
}

/// Looks up this volume's on-disk size from `podman system df -v --format
/// json`. Podman's per-volume rows key the volume under `Name` or
/// `VolumeName` depending on version, and the size under `Size` or
/// `ReclaimableSize`'s sibling `Size` field; we scan both shapes. Returns
/// `None` on any parse failure or command error rather than propagating —
/// size is a nice-to-have, not required for the response to be useful.
async fn volume_size_bytes(podman: &Podman, name: &str) -> Option<u64> {
    let mut cmd = podman.base_command();
    cmd.arg("system").arg("df").arg("-v").arg("--format=json");
    let out = podman.run_capture(cmd).await.ok()?;
    let value: serde_json::Value = serde_json::from_str(&out).ok()?;
    let rows = value.get("Volumes").and_then(serde_json::Value::as_array)?;
    rows.iter().find_map(|row| {
        let row_name = row
            .get("VolumeName")
            .or_else(|| row.get("Name"))
            .and_then(serde_json::Value::as_str)?;
        if row_name != name {
            return None;
        }
        row.get("Size").and_then(serde_json::Value::as_u64)
    })
}

/// Lists the names of containers currently mounting this volume, via `podman
/// ps -a --filter volume=<name> --format json`. Reuses the shared container
/// list parser so podman-version quirks in the `ps` JSON shape are handled in
/// one place. Returns an empty vec on any command/parse error — an unlistable
/// "in use by" set is not fatal to the inspect response.
async fn volume_in_use_by(podman: &Podman, name: &str) -> Vec<String> {
    let mut cmd = podman.base_command();
    cmd.arg("ps")
        .arg("-a")
        .arg("--filter")
        .arg(format!("volume={name}"))
        .arg("--format=json");
    let out = match podman.run_capture(cmd).await {
        Ok(out) => out,
        Err(_) => return Vec::new(),
    };
    match parse::parse_container_list(&out) {
        Ok(containers) => containers
            .into_iter()
            .map(|c| c.names.first().cloned().unwrap_or(c.id.0))
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[instrument(skip(podman))]
pub async fn prune(podman: &Podman) -> Result<Vec<VolumeId>> {
    let mut cmd = podman.base_command();
    cmd.arg("volume").arg("prune").arg("--force");
    let out = podman.run_capture(cmd).await?;
    // `podman volume prune --force` prints one removed volume name per line.
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| VolumeId(l.trim().to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::podman::PodmanConfig;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// Writes an executable shell script that dispatches on the podman
    /// subcommand (first arg) and prints the given real-world-shaped JSON
    /// fixtures, mimicking `podman volume inspect` / `podman system df -v` /
    /// `podman ps -a --filter volume=`. Returns a [`Podman`] configured to
    /// invoke it as the "binary".
    fn fake_podman(dir: &tempfile::TempDir) -> Podman {
        let script_path = dir.path().join("podman");
        let script = r#"#!/bin/sh
case "$1" in
  volume)
    cat <<'EOF'
[{"Name":"data-vol","Driver":"local","Mountpoint":"/var/lib/containers/storage/volumes/data-vol/_data","CreatedAt":"2026-05-20T10:00:00Z","Labels":{},"Options":{}}]
EOF
    ;;
  system)
    cat <<'EOF'
{"Volumes":[{"VolumeName":"data-vol","Links":2,"Size":104857600,"ReclaimableSize":0},{"VolumeName":"other-vol","Size":10}]}
EOF
    ;;
  ps)
    cat <<'EOF'
[{"Id":"c1","Names":["web"],"Image":"nginx","State":"running","Status":"Up 2 hours","Created":"2026-05-20T10:05:00Z"},{"Id":"c2","Names":["worker"],"Image":"alpine","State":"exited","Status":"Exited","Created":"2026-05-20T10:06:00Z"}]
EOF
    ;;
  *)
    echo "unexpected subcommand: $1" 1>&2
    exit 1
    ;;
esac
"#;
        let mut f = std::fs::File::create(&script_path).expect("write fake podman script");
        f.write_all(script.as_bytes())
            .expect("write fake podman script contents");
        let mut perms = f.metadata().expect("script metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake podman script");
        Podman::with_config(PodmanConfig {
            binary: Some(script_path),
            root: None,
            runroot: None,
        })
    }

    #[tokio::test]
    async fn volume_size_bytes_matches_row_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let podman = fake_podman(&dir);
        let size = volume_size_bytes(&podman, "data-vol").await;
        assert_eq!(size, Some(104_857_600));
    }

    #[tokio::test]
    async fn volume_size_bytes_none_when_name_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let podman = fake_podman(&dir);
        let size = volume_size_bytes(&podman, "missing-vol").await;
        assert_eq!(size, None);
    }

    #[tokio::test]
    async fn volume_in_use_by_lists_container_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let podman = fake_podman(&dir);
        let names = volume_in_use_by(&podman, "data-vol").await;
        assert_eq!(names, vec!["web".to_string(), "worker".to_string()]);
    }

    #[tokio::test]
    async fn inspect_detail_composes_base_size_and_in_use_by() {
        let dir = tempfile::tempdir().expect("tempdir");
        let podman = fake_podman(&dir);
        let detail = inspect_detail(&podman, &VolumeId::from("data-vol"))
            .await
            .expect("inspect_detail");
        assert_eq!(detail.name, "data-vol");
        assert_eq!(detail.driver, "local");
        assert_eq!(
            detail.mountpoint,
            "/var/lib/containers/storage/volumes/data-vol/_data"
        );
        assert!(detail.created.is_some());
        assert_eq!(detail.size_bytes, Some(104_857_600));
        assert_eq!(
            detail.in_use_by,
            vec!["web".to_string(), "worker".to_string()]
        );
    }
}
