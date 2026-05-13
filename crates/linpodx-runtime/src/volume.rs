use crate::parse;
use crate::podman::{map_not_found, Podman};
use linpodx_common::error::Result;
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
