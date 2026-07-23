use crate::parse;
use crate::podman::{map_not_found, Podman};
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::{
    NetworkAttachResponse, NetworkInspectDetailResponse, NetworkMember, NetworkSubnet,
};
use linpodx_common::ipc::{NetworkCreateParams, NetworkRemoveParams};
use linpodx_common::state::{NetworkInspect, NetworkSummary};
use linpodx_common::types::NetworkId;
use serde_json::Value;
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

/// Phase 27 — richer network inspect that also surfaces every subnet/gateway
/// pair and the containers currently attached to the network (with their
/// per-network IPv4 + MAC when podman reports them).
///
/// Primary source is `podman network inspect <name>` — modern netavark output
/// carries a `containers` map keyed by container id, each with a `name` and an
/// `interfaces` object. When that map is absent (some rootless / stopped
/// states omit it) we fall back to a lighter `podman ps --filter network=<name>`
/// sweep which at least recovers the running members' ids + names.
#[instrument(skip(podman))]
pub async fn inspect_detail(
    podman: &Podman,
    name: &NetworkId,
) -> Result<NetworkInspectDetailResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("inspect").arg(&name.0);
    let out = match podman.run_capture(cmd).await {
        Ok(s) => s,
        Err(e) => return Err(map_not_found(e, &name.0)),
    };
    let value: Value = serde_json::from_str(&out)?;
    let obj = value
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::NotFound(format!("network '{}'", name.0)))?;

    let net_name = obj
        .get("name")
        .or_else(|| obj.get("Name"))
        .and_then(Value::as_str)
        .unwrap_or(&name.0)
        .to_string();
    let driver = obj
        .get("driver")
        .or_else(|| obj.get("Driver"))
        .and_then(Value::as_str)
        .unwrap_or("bridge")
        .to_string();
    let internal = obj
        .get("internal")
        .or_else(|| obj.get("Internal"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let dns_enabled = obj
        .get("dns_enabled")
        .or_else(|| obj.get("DnsEnabled"))
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let subnets = parse_all_subnets(obj);
    let mut containers = parse_members(obj);
    if containers.is_empty() {
        containers = members_via_ps(podman, &name.0).await.unwrap_or_default();
    }

    Ok(NetworkInspectDetailResponse {
        name: net_name,
        driver,
        subnets,
        dns_enabled,
        internal,
        containers,
    })
}

/// Attach a running container to a network (`podman network connect`).
#[instrument(skip(podman))]
pub async fn connect(
    podman: &Podman,
    network: &str,
    container: &str,
) -> Result<NetworkAttachResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("network")
        .arg("connect")
        .arg(network)
        .arg(container);
    podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, network))?;
    Ok(NetworkAttachResponse {
        network: network.to_string(),
        container: container.to_string(),
        status: "connected".to_string(),
    })
}

/// Detach a container from a network (`podman network disconnect [--force]`).
#[instrument(skip(podman))]
pub async fn disconnect(
    podman: &Podman,
    network: &str,
    container: &str,
    force: bool,
) -> Result<NetworkAttachResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("network").arg("disconnect");
    if force {
        cmd.arg("--force");
    }
    cmd.arg(network).arg(container);
    podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_not_found(e, network))?;
    Ok(NetworkAttachResponse {
        network: network.to_string(),
        container: container.to_string(),
        status: "disconnected".to_string(),
    })
}

/// Every `subnet`/`gateway` pair from a network-inspect object. Gateway falls
/// back to an empty string when podman does not report one for a subnet.
fn parse_all_subnets(v: &Value) -> Vec<NetworkSubnet> {
    v.get("subnets")
        .or_else(|| v.get("Subnets"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let subnet = s
                        .get("subnet")
                        .or_else(|| s.get("Subnet"))
                        .and_then(Value::as_str)?
                        .to_string();
                    let gateway = s
                        .get("gateway")
                        .or_else(|| s.get("Gateway"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some(NetworkSubnet { subnet, gateway })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Connected containers from the netavark `containers` map. Empty when the map
/// is absent (caller then falls back to `members_via_ps`).
fn parse_members(v: &Value) -> Vec<NetworkMember> {
    let Some(map) = v.get("containers").and_then(Value::as_object) else {
        return Vec::new();
    };
    map.iter()
        .map(|(id, entry)| {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let (ipv4, mac) = first_interface_addr(entry);
            NetworkMember {
                id: id.clone(),
                name,
                ipv4,
                mac,
            }
        })
        .collect()
}

/// First interface's IPv4 (CIDR suffix stripped) + MAC for a member entry.
fn first_interface_addr(entry: &Value) -> (Option<String>, Option<String>) {
    let Some(ifaces) = entry.get("interfaces").and_then(Value::as_object) else {
        return (None, None);
    };
    let Some((_, iface)) = ifaces.iter().next() else {
        return (None, None);
    };
    let ipv4 = iface
        .get("subnets")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|s| s.get("ipnet").or_else(|| s.get("IPNet")))
        .and_then(Value::as_str)
        .map(|s| s.split('/').next().unwrap_or(s).to_string());
    let mac = iface
        .get("mac_address")
        .or_else(|| iface.get("MacAddress"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from);
    (ipv4, mac)
}

/// Fallback member list via `podman ps --filter network=<name>`. Only running
/// containers are reported and no per-network IP/MAC is available this way.
async fn members_via_ps(podman: &Podman, network: &str) -> Result<Vec<NetworkMember>> {
    let mut cmd = podman.base_command();
    cmd.arg("ps")
        .arg("--filter")
        .arg(format!("network={network}"))
        .arg("--format=json");
    let out = podman.run_capture(cmd).await?;
    let value: Value = serde_json::from_str(&out)?;
    let arr = value.as_array().cloned().unwrap_or_default();
    Ok(arr
        .iter()
        .filter_map(|c| {
            let id = c
                .get("Id")
                .or_else(|| c.get("ID"))
                .or_else(|| c.get("id"))
                .and_then(Value::as_str)?;
            let name = c
                .get("Names")
                .and_then(|n| n.as_array())
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .or_else(|| c.get("Names").and_then(Value::as_str))
                .unwrap_or("")
                .to_string();
            Some(NetworkMember {
                id: id.to_string(),
                name,
                ipv4: None,
                mac: None,
            })
        })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A trimmed but realistic single-element `podman network inspect` object
    /// as produced by netavark on Podman 5.x.
    fn netavark_inspect_obj() -> Value {
        json!({
            "name": "linpodx-net",
            "id": "1e2d3c4b5a69",
            "driver": "bridge",
            "network_interface": "podman1",
            "subnets": [
                { "subnet": "10.89.0.0/24", "gateway": "10.89.0.1" },
                { "subnet": "fd00:dead::/64", "gateway": "fd00:dead::1" }
            ],
            "ipv6_enabled": true,
            "internal": false,
            "dns_enabled": true,
            "containers": {
                "abc123def456": {
                    "name": "web",
                    "interfaces": {
                        "eth0": {
                            "subnets": [
                                { "ipnet": "10.89.0.2/24", "gateway": "10.89.0.1" }
                            ],
                            "mac_address": "aa:bb:cc:dd:ee:01"
                        }
                    }
                },
                "789fedcba012": {
                    "name": "db",
                    "interfaces": {
                        "eth0": {
                            "subnets": [
                                { "ipnet": "10.89.0.3/24", "gateway": "10.89.0.1" }
                            ],
                            "mac_address": "aa:bb:cc:dd:ee:02"
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn parse_all_subnets_reads_every_pair() {
        let subnets = parse_all_subnets(&netavark_inspect_obj());
        assert_eq!(subnets.len(), 2);
        assert_eq!(subnets[0].subnet, "10.89.0.0/24");
        assert_eq!(subnets[0].gateway, "10.89.0.1");
        assert_eq!(subnets[1].subnet, "fd00:dead::/64");
    }

    #[test]
    fn parse_all_subnets_empty_when_absent() {
        assert!(parse_all_subnets(&json!({ "name": "x" })).is_empty());
    }

    #[test]
    fn parse_members_extracts_ip_and_mac() {
        let mut members = parse_members(&netavark_inspect_obj());
        members.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(members.len(), 2);
        let db = &members[0];
        assert_eq!(db.name, "db");
        assert_eq!(db.id, "789fedcba012");
        assert_eq!(db.ipv4.as_deref(), Some("10.89.0.3"));
        assert_eq!(db.mac.as_deref(), Some("aa:bb:cc:dd:ee:02"));
        let web = &members[1];
        assert_eq!(web.name, "web");
        assert_eq!(web.ipv4.as_deref(), Some("10.89.0.2"));
    }

    #[test]
    fn parse_members_empty_when_no_containers_map() {
        assert!(parse_members(&json!({ "name": "x" })).is_empty());
    }

    #[test]
    fn first_interface_addr_handles_missing_interfaces() {
        assert_eq!(
            first_interface_addr(&json!({ "name": "solo" })),
            (None, None)
        );
    }

    #[test]
    fn first_interface_addr_strips_cidr_and_empty_mac() {
        let entry = json!({
            "name": "svc",
            "interfaces": {
                "eth0": {
                    "subnets": [ { "ipnet": "192.168.5.20/24" } ],
                    "mac_address": ""
                }
            }
        });
        let (ip, mac) = first_interface_addr(&entry);
        assert_eq!(ip.as_deref(), Some("192.168.5.20"));
        assert_eq!(mac, None);
    }
}
