use crate::parse;
use crate::podman::{map_not_found, Podman};
use linpodx_common::error::Result;
use linpodx_common::ipc::{NetworkCreateParams, NetworkRemoveParams};
use linpodx_common::state::{NetworkInspect, NetworkSummary};
use linpodx_common::types::NetworkId;
use tracing::instrument;

#[instrument(skip(podman))]
pub async fn list(podman: &Podman) -> Result<Vec<NetworkSummary>> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("ls").arg("--format=json");
    let out = podman.run_capture(cmd).await?;
    parse::parse_network_list(&out)
}

#[instrument(skip(podman))]
pub async fn create(podman: &Podman, params: &NetworkCreateParams) -> Result<NetworkId> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("create");
    if let Some(driver) = &params.driver {
        cmd.arg("--driver").arg(driver);
    }
    if let Some(subnet) = &params.subnet {
        cmd.arg("--subnet").arg(subnet);
    }
    if let Some(gw) = &params.gateway {
        cmd.arg("--gateway").arg(gw);
    }
    if params.internal {
        cmd.arg("--internal");
    }
    if !params.dns_enabled {
        cmd.arg("--disable-dns");
    }
    for (k, v) in &params.labels {
        cmd.arg("--label").arg(format!("{k}={v}"));
    }
    cmd.arg(&params.name);
    let out = podman.run_capture(cmd).await?;
    // `podman network create <name>` prints the network name on success.
    let name = out.trim().to_string();
    if name.is_empty() {
        return Err(linpodx_common::error::Error::Runtime {
            message: "podman network create returned empty name".into(),
        });
    }
    Ok(NetworkId(name))
}

#[instrument(skip(podman))]
pub async fn remove(podman: &Podman, params: &NetworkRemoveParams) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("rm");
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
pub async fn inspect(podman: &Podman, name: &NetworkId) -> Result<NetworkInspect> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("inspect").arg(&name.0);
    let out = match podman.run_capture(cmd).await {
        Ok(s) => s,
        Err(e) => return Err(map_not_found(e, &name.0)),
    };
    parse::parse_network_inspect(&out)
}

#[instrument(skip(podman))]
pub async fn prune(podman: &Podman) -> Result<Vec<NetworkId>> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("prune").arg("--force");
    let out = podman.run_capture(cmd).await?;
    // Same pattern as `podman volume prune` — one removed network per line.
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| NetworkId(l.trim().to_string()))
        .collect())
}
