//! Parsers for `podman` JSON output.
//!
//! Podman's `--format=json` output schemas vary slightly across versions; we
//! parse permissively into our own `linpodx-common` types and stash the raw
//! JSON in `ContainerInspect::raw` for fields we don't model yet.

use chrono::{DateTime, TimeZone, Utc};
use linpodx_common::error::{Error, Result};
use linpodx_common::state::{
    ContainerInspect, ContainerState, ContainerSummary, ImageConfig, ImageInspect, ImageSummary,
    MountInfo, NetworkInspect, NetworkSettings, NetworkSummary, VolumeInspect, VolumeSummary,
};
use linpodx_common::types::{ContainerId, ImageId, NetworkId, VolumeId};
use serde_json::Value;
use std::collections::HashMap;

pub fn parse_container_list(json: &str) -> Result<Vec<ContainerSummary>> {
    let value: Value = serde_json::from_str(json)?;
    let arr = value.as_array().ok_or_else(|| Error::Runtime {
        message: "podman ps did not return an array".into(),
    })?;
    arr.iter().map(parse_container_summary).collect()
}

fn parse_container_summary(v: &Value) -> Result<ContainerSummary> {
    let id = v
        .get("Id")
        .or_else(|| v.get("ID"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "container missing Id".into(),
        })?;
    let names = v
        .get("Names")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let image = v
        .get("Image")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let state_raw = v.get("State").and_then(Value::as_str).unwrap_or("");
    let status = v
        .get("Status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let created = parse_created(v.get("Created"))?;
    let command = v.get("Command").and_then(|c| match c {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => Some(
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    });
    // Podman 5.x `ps --format json` emits `Ports` as either `null` (nothing
    // published — including exposed-only containers) or an array of objects
    // `{host_ip, container_port, host_port, range, protocol}`. Older
    // podman/docker variants sometimes emit a plain string per entry, which we
    // pass through untouched. `null` yields an empty vec via `unwrap_or_default`.
    let ports = v
        .get("Ports")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(parse_port_entry).collect())
        .unwrap_or_default();

    Ok(ContainerSummary {
        id: ContainerId::from(id),
        names,
        image,
        state: ContainerState::parse_lossy(state_raw),
        status,
        created,
        command,
        ports,
    })
}

pub fn parse_container_inspect(json: &str) -> Result<ContainerInspect> {
    let value: Value = serde_json::from_str(json)?;
    // `podman inspect` returns an array of objects.
    let obj = value
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::NotFound("container".into()))?;

    let id = obj
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "inspect missing Id".into(),
        })?;
    let name = obj
        .get("Name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let image = obj
        .get("ImageName")
        .or_else(|| obj.get("Image"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let image_id = obj.get("Image").and_then(Value::as_str).map(ImageId::from);

    let state_obj = obj.get("State");
    let state_str = state_obj
        .and_then(|s| s.get("Status"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let status = state_obj
        .and_then(|s| s.get("Status"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let created = parse_created(obj.get("Created"))?;

    let cfg = obj.get("Config");
    let command = cfg
        .and_then(|c| c.get("Cmd"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let args = obj
        .get("Args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let env = cfg
        .and_then(|c| c.get("Env"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    e.as_str().and_then(|s| {
                        s.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let labels: HashMap<String, String> = cfg
        .and_then(|c| c.get("Labels"))
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|vs| (k.clone(), vs.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mounts = obj
        .get("Mounts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let o = m.as_object()?;
                    Some(MountInfo {
                        source: o.get("Source").and_then(Value::as_str)?.to_string(),
                        destination: o.get("Destination").and_then(Value::as_str)?.to_string(),
                        kind: o
                            .get("Type")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        read_only: !o.get("RW").and_then(Value::as_bool).unwrap_or(true),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let net_obj = obj.get("NetworkSettings").and_then(Value::as_object);
    let network_settings = NetworkSettings {
        ip_address: net_obj
            .and_then(|n| n.get("IPAddress"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from),
        ports: net_obj
            .and_then(|n| n.get("Ports"))
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default(),
    };

    Ok(ContainerInspect {
        id: ContainerId::from(id),
        name,
        image,
        image_id,
        state: ContainerState::parse_lossy(state_str),
        status,
        created,
        command,
        args,
        env,
        mounts,
        network_settings,
        labels,
        raw: Some(obj.clone()),
    })
}

// =========================
// Image parsers
// =========================

pub fn parse_image_list(json: &str) -> Result<Vec<ImageSummary>> {
    let value: Value = serde_json::from_str(json)?;
    let arr = value.as_array().ok_or_else(|| Error::Runtime {
        message: "podman images did not return an array".into(),
    })?;
    arr.iter().map(parse_image_summary).collect()
}

fn parse_image_summary(v: &Value) -> Result<ImageSummary> {
    let id = v
        .get("Id")
        .or_else(|| v.get("ID"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "image missing Id".into(),
        })?;
    let repo_tags = string_array(v.get("Names").or_else(|| v.get("RepoTags")));
    let mut repo_digests = string_array(v.get("RepoDigests"));
    if repo_digests.is_empty() {
        if let Some(d) = v.get("Digest").and_then(Value::as_str) {
            if !d.is_empty() {
                repo_digests.push(d.to_string());
            }
        }
    }
    let size_bytes = v.get("Size").and_then(Value::as_u64).unwrap_or(0);
    let created = parse_created(v.get("Created"))?;
    let labels = string_map(v.get("Labels"));
    Ok(ImageSummary {
        id: ImageId::from(id),
        repo_tags,
        repo_digests,
        size_bytes,
        created,
        labels,
    })
}

pub fn parse_image_inspect(json: &str) -> Result<ImageInspect> {
    let value: Value = serde_json::from_str(json)?;
    let obj = value
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::NotFound("image".into()))?;

    let id = obj
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "image inspect missing Id".into(),
        })?;
    let repo_tags = string_array(obj.get("RepoTags"));
    let repo_digests = string_array(obj.get("RepoDigests"));
    let size_bytes = obj.get("Size").and_then(Value::as_u64).unwrap_or(0);
    let virtual_size_bytes = obj
        .get("VirtualSize")
        .and_then(Value::as_u64)
        .unwrap_or(size_bytes);
    let architecture = obj
        .get("Architecture")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let os = obj
        .get("Os")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let created = parse_created(obj.get("Created"))?;
    let labels = string_map(obj.get("Labels"));

    let cfg = obj.get("Config");
    let config = ImageConfig {
        env: string_array(cfg.and_then(|c| c.get("Env"))),
        cmd: string_array(cfg.and_then(|c| c.get("Cmd"))),
        entrypoint: string_array(cfg.and_then(|c| c.get("Entrypoint"))),
        working_dir: cfg
            .and_then(|c| c.get("WorkingDir"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from),
        exposed_ports: cfg
            .and_then(|c| c.get("ExposedPorts"))
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default(),
        user: cfg
            .and_then(|c| c.get("User"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from),
    };

    Ok(ImageInspect {
        id: ImageId::from(id),
        repo_tags,
        repo_digests,
        size_bytes,
        virtual_size_bytes,
        architecture,
        os,
        created,
        config,
        labels,
        raw: Some(obj.clone()),
    })
}

// =========================
// Volume parsers
// =========================

pub fn parse_volume_list(json: &str) -> Result<Vec<VolumeSummary>> {
    let value: Value = serde_json::from_str(json)?;
    let arr = value.as_array().ok_or_else(|| Error::Runtime {
        message: "podman volume ls did not return an array".into(),
    })?;
    arr.iter().map(parse_volume_summary).collect()
}

fn parse_volume_summary(v: &Value) -> Result<VolumeSummary> {
    let name = v
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "volume missing Name".into(),
        })?;
    Ok(VolumeSummary {
        name: VolumeId::from(name),
        driver: v
            .get("Driver")
            .and_then(Value::as_str)
            .unwrap_or("local")
            .to_string(),
        mountpoint: v
            .get("Mountpoint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        created: parse_created(v.get("CreatedAt").or_else(|| v.get("Created")))?,
        labels: string_map(v.get("Labels")),
    })
}

pub fn parse_volume_inspect(json: &str) -> Result<VolumeInspect> {
    let value: Value = serde_json::from_str(json)?;
    let obj = value
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::NotFound("volume".into()))?;
    let name = obj
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "volume inspect missing Name".into(),
        })?;
    Ok(VolumeInspect {
        name: VolumeId::from(name),
        driver: obj
            .get("Driver")
            .and_then(Value::as_str)
            .unwrap_or("local")
            .to_string(),
        mountpoint: obj
            .get("Mountpoint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        created: parse_created(obj.get("CreatedAt").or_else(|| obj.get("Created")))?,
        labels: string_map(obj.get("Labels")),
        options: string_map(obj.get("Options")),
        raw: Some(obj.clone()),
    })
}

// =========================
// Network parsers
// =========================

pub fn parse_network_list(json: &str) -> Result<Vec<NetworkSummary>> {
    let value: Value = serde_json::from_str(json)?;
    let arr = value.as_array().ok_or_else(|| Error::Runtime {
        message: "podman network ls did not return an array".into(),
    })?;
    arr.iter().map(parse_network_summary).collect()
}

fn parse_network_summary(v: &Value) -> Result<NetworkSummary> {
    let id = v
        .get("id")
        .or_else(|| v.get("Id"))
        .or_else(|| v.get("ID"))
        .or_else(|| v.get("name"))
        .or_else(|| v.get("Name"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "network missing id/Name".into(),
        })?;
    let name = v
        .get("name")
        .or_else(|| v.get("Name"))
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_string();
    let driver = v
        .get("driver")
        .or_else(|| v.get("Driver"))
        .and_then(Value::as_str)
        .unwrap_or("bridge")
        .to_string();
    let (subnet, gateway) = extract_subnet_gateway(v);
    Ok(NetworkSummary {
        id: NetworkId::from(id),
        name,
        driver,
        subnet,
        gateway,
        created: parse_created(v.get("created").or_else(|| v.get("Created")))?,
        labels: string_map(v.get("labels").or_else(|| v.get("Labels"))),
    })
}

pub fn parse_network_inspect(json: &str) -> Result<NetworkInspect> {
    let value: Value = serde_json::from_str(json)?;
    let obj = value
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::NotFound("network".into()))?;
    let id = obj
        .get("id")
        .or_else(|| obj.get("Id"))
        .or_else(|| obj.get("ID"))
        .or_else(|| obj.get("name"))
        .or_else(|| obj.get("Name"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "network inspect missing id/Name".into(),
        })?;
    let name = obj
        .get("name")
        .or_else(|| obj.get("Name"))
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_string();
    let driver = obj
        .get("driver")
        .or_else(|| obj.get("Driver"))
        .and_then(Value::as_str)
        .unwrap_or("bridge")
        .to_string();
    let (subnet, gateway) = extract_subnet_gateway(obj);
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
    Ok(NetworkInspect {
        id: NetworkId::from(id),
        name,
        driver,
        subnet,
        gateway,
        internal,
        dns_enabled,
        created: parse_created(obj.get("created").or_else(|| obj.get("Created")))?,
        labels: string_map(obj.get("labels").or_else(|| obj.get("Labels"))),
        raw: Some(obj.clone()),
    })
}

/// Pull the first IPv4 subnet/gateway out of a `subnets: [{subnet, gateway}, ...]` array.
fn extract_subnet_gateway(v: &Value) -> (Option<String>, Option<String>) {
    let subnets = v
        .get("subnets")
        .or_else(|| v.get("Subnets"))
        .and_then(Value::as_array);
    if let Some(arr) = subnets {
        if let Some(first) = arr.first() {
            let subnet = first
                .get("subnet")
                .or_else(|| first.get("Subnet"))
                .and_then(Value::as_str)
                .map(String::from);
            let gateway = first
                .get("gateway")
                .or_else(|| first.get("Gateway"))
                .and_then(Value::as_str)
                .map(String::from);
            return (subnet, gateway);
        }
    }
    (None, None)
}

// =========================
// Helpers
// =========================

/// Render one `podman ps` port entry into the human `host_ip:host->container/proto`
/// string the UI expects (matching podman's own PORTS column, e.g.
/// `127.0.0.1:3390->3389/tcp`). Accepts either the Podman 5.x object form
/// (`{host_ip, container_port, host_port, range, protocol}`) or a pre-formatted
/// string (passed through). Port ranges (`range > 1`) render as
/// `host-lo-host_hi->ctr_lo-ctr_hi/proto`. Returns `None` for unrecognized shapes.
fn parse_port_entry(x: &Value) -> Option<String> {
    if let Some(s) = x.as_str() {
        let t = s.trim();
        return if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        };
    }
    let o = x.as_object()?;
    let host_ip = o.get("host_ip").and_then(Value::as_str).unwrap_or("");
    let host_port = o.get("host_port").and_then(Value::as_u64).unwrap_or(0);
    let container_port = o.get("container_port").and_then(Value::as_u64).unwrap_or(0);
    let range = o.get("range").and_then(Value::as_u64).unwrap_or(1).max(1);
    let protocol = o.get("protocol").and_then(Value::as_str).unwrap_or("tcp");

    let host_part = if range > 1 {
        format!("{host_port}-{}", host_port + range - 1)
    } else {
        host_port.to_string()
    };
    let container_part = if range > 1 {
        format!("{container_port}-{}", container_port + range - 1)
    } else {
        container_port.to_string()
    };
    let mapping = format!("{host_part}->{container_part}/{protocol}");
    Some(if host_ip.is_empty() {
        mapping
    } else {
        format!("{host_ip}:{mapping}")
    })
}

fn string_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn string_map(v: Option<&Value>) -> HashMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse Podman's `Created` field, which is sometimes a unix timestamp (seconds, integer)
/// and sometimes an RFC3339 string.
fn parse_created(v: Option<&Value>) -> Result<DateTime<Utc>> {
    match v {
        Some(Value::Number(n)) => {
            if let Some(secs) = n.as_i64() {
                return Utc
                    .timestamp_opt(secs, 0)
                    .single()
                    .ok_or_else(|| Error::Runtime {
                        message: format!("invalid unix timestamp {secs}"),
                    });
            }
            Err(Error::Runtime {
                message: format!("created field is non-integer number: {n}"),
            })
        }
        Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| Error::Runtime {
                message: format!("invalid created timestamp '{s}': {e}"),
            }),
        _ => Ok(Utc::now()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_image_list_minimal() {
        let v = json!([{
            "Id": "sha256:abc",
            "Names": ["docker.io/library/alpine:latest"],
            "Size": 5_000_000_u64,
            "Created": 1_746_700_000,
            "Labels": {"org": "linpodx"}
        }]);
        let parsed = parse_image_list(&v.to_string()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id.as_str(), "sha256:abc");
        assert_eq!(parsed[0].repo_tags, vec!["docker.io/library/alpine:latest"]);
        assert_eq!(parsed[0].size_bytes, 5_000_000);
        assert_eq!(parsed[0].labels.get("org"), Some(&"linpodx".to_string()));
    }

    #[test]
    fn parse_image_inspect_minimal() {
        let v = json!([{
            "Id": "sha256:def",
            "RepoTags": ["alpine:latest"],
            "RepoDigests": ["docker.io/library/alpine@sha256:zzz"],
            "Size": 5_300_000_u64,
            "VirtualSize": 5_300_000_u64,
            "Architecture": "amd64",
            "Os": "linux",
            "Created": "2026-05-09T10:00:00Z",
            "Config": {
                "Cmd": ["/bin/sh"],
                "Env": ["PATH=/usr/bin"],
                "WorkingDir": "/",
                "ExposedPorts": {"80/tcp": {}},
                "User": ""
            },
            "Labels": null
        }]);
        let p = parse_image_inspect(&v.to_string()).unwrap();
        assert_eq!(p.id.as_str(), "sha256:def");
        assert_eq!(p.architecture, "amd64");
        assert_eq!(p.config.cmd, vec!["/bin/sh"]);
        assert_eq!(p.config.exposed_ports, vec!["80/tcp"]);
        assert!(p.config.user.is_none());
    }

    #[test]
    fn parse_volume_list_minimal() {
        let v = json!([{
            "Name": "demo-data",
            "Driver": "local",
            "Mountpoint": "/var/home/k/.local/share/containers/storage/volumes/demo-data/_data",
            "CreatedAt": "2026-05-09T11:00:00Z",
            "Labels": {}
        }]);
        let p = parse_volume_list(&v.to_string()).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name.as_str(), "demo-data");
        assert_eq!(p[0].driver, "local");
        assert!(p[0].mountpoint.contains("demo-data"));
    }

    #[test]
    fn parse_network_list_with_subnet() {
        let v = json!([{
            "name": "demo-net",
            "id": "abcd1234",
            "driver": "bridge",
            "internal": false,
            "dns_enabled": true,
            "subnets": [
                {"subnet": "10.99.0.0/24", "gateway": "10.99.0.1"}
            ],
            "created": "2026-05-09T12:00:00Z",
            "labels": {}
        }]);
        let p = parse_network_list(&v.to_string()).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "demo-net");
        assert_eq!(p[0].driver, "bridge");
        assert_eq!(p[0].subnet.as_deref(), Some("10.99.0.0/24"));
        assert_eq!(p[0].gateway.as_deref(), Some("10.99.0.1"));
    }

    #[test]
    fn parse_network_inspect_defaults() {
        let v = json!([{
            "name": "tiny-net",
            "id": "deadbeef",
            "driver": "bridge",
            "created": "2026-05-09T12:00:00Z"
        }]);
        let p = parse_network_inspect(&v.to_string()).unwrap();
        assert_eq!(p.name, "tiny-net");
        assert!(p.dns_enabled, "dns_enabled should default to true");
        assert!(!p.internal);
        assert!(p.subnet.is_none());
    }

    #[test]
    fn parse_summary_minimal() {
        let v = json!([{
            "Id": "abc123",
            "Names": ["happy_test"],
            "Image": "alpine:latest",
            "State": "running",
            "Status": "Up 5 seconds",
            "Created": 1746630000,
            "Command": ["sleep", "infinity"],
            "Ports": []
        }]);
        let parsed = parse_container_list(&v.to_string()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id.as_str(), "abc123");
        assert_eq!(parsed[0].state, ContainerState::Running);
        assert_eq!(parsed[0].command.as_deref(), Some("sleep infinity"));
    }

    #[test]
    fn parse_ports_null_yields_empty() {
        // Podman 5.8 emits `Ports: null` for exposed-only / no-publish containers.
        let v = json!([{
            "Id": "abc",
            "Names": ["open-webui"],
            "Image": "ghcr.io/open-webui/open-webui:latest",
            "State": "running",
            "Status": "Up 3 days",
            "Created": 1746630000,
            "Command": ["bash", "start.sh"],
            "Ports": null
        }]);
        let parsed = parse_container_list(&v.to_string()).unwrap();
        assert!(parsed[0].ports.is_empty());
    }

    #[test]
    fn parse_ports_object_array_real_5x_sample() {
        // Real captured `podman 5.8.2 ps --format json` Ports for the
        // `winpodx-windows` container (host: 127.0.0.1 published, tcp + udp).
        let v = json!([{
            "Id": "a65daf879a80",
            "Names": ["winpodx-windows"],
            "Image": "docker.io/dockurr/windows",
            "State": "running",
            "Status": "Up 24 hours",
            "Created": 1746630000,
            "Command": ["/run/entry.sh"],
            "Ports": [
                {"host_ip": "127.0.0.1", "container_port": 3389, "host_port": 3390, "range": 1, "protocol": "tcp"},
                {"host_ip": "127.0.0.1", "container_port": 445, "host_port": 4445, "range": 1, "protocol": "tcp"},
                {"host_ip": "127.0.0.1", "container_port": 8006, "host_port": 8007, "range": 1, "protocol": "tcp"},
                {"host_ip": "127.0.0.1", "container_port": 8765, "host_port": 8765, "range": 1, "protocol": "tcp"},
                {"host_ip": "127.0.0.1", "container_port": 3389, "host_port": 3390, "range": 1, "protocol": "udp"}
            ]
        }]);
        let parsed = parse_container_list(&v.to_string()).unwrap();
        assert_eq!(
            parsed[0].ports,
            vec![
                "127.0.0.1:3390->3389/tcp",
                "127.0.0.1:4445->445/tcp",
                "127.0.0.1:8007->8006/tcp",
                "127.0.0.1:8765->8765/tcp",
                "127.0.0.1:3390->3389/udp",
            ]
        );
    }

    #[test]
    fn parse_ports_wildcard_host_and_range() {
        // `0.0.0.0` bind (real `graftx-windows-m2` shape) plus a synthetic
        // multi-port range to exercise range expansion.
        let v = json!([{
            "Id": "d5711c995475",
            "Names": ["graftx-windows-m2"],
            "Image": "graftx-windows-m2-pod:local",
            "State": "running",
            "Status": "Up 3 days",
            "Created": 1746630000,
            "Command": ["/run.sh"],
            "Ports": [
                {"host_ip": "0.0.0.0", "container_port": 3389, "host_port": 3389, "range": 1, "protocol": "tcp"},
                {"host_ip": "", "container_port": 8000, "host_port": 8000, "range": 3, "protocol": "tcp"}
            ]
        }]);
        let parsed = parse_container_list(&v.to_string()).unwrap();
        assert_eq!(
            parsed[0].ports,
            vec!["0.0.0.0:3389->3389/tcp", "8000-8002->8000-8002/tcp"]
        );
    }

    #[test]
    fn parse_ports_string_passthrough() {
        // Legacy string form is passed through verbatim.
        let v = json!([{
            "Id": "legacy",
            "Names": ["old"],
            "Image": "alpine",
            "State": "running",
            "Status": "Up",
            "Created": 1746630000,
            "Command": ["sh"],
            "Ports": ["0.0.0.0:80->80/tcp"]
        }]);
        let parsed = parse_container_list(&v.to_string()).unwrap();
        assert_eq!(parsed[0].ports, vec!["0.0.0.0:80->80/tcp"]);
    }

    #[test]
    fn parse_inspect_minimal() {
        let v = json!([{
            "Id": "deadbeef",
            "Name": "/my-container",
            "Image": "sha256:abcdef",
            "ImageName": "alpine:latest",
            "State": { "Status": "exited" },
            "Created": "2026-05-08T10:00:00Z",
            "Args": [],
            "Config": {
                "Cmd": ["echo", "hi"],
                "Env": ["FOO=bar", "BAZ=qux"],
                "Labels": {"app": "linpodx"}
            },
            "Mounts": [],
            "NetworkSettings": { "IPAddress": "", "Ports": {} }
        }]);
        let parsed = parse_container_inspect(&v.to_string()).unwrap();
        assert_eq!(parsed.id.as_str(), "deadbeef");
        assert_eq!(parsed.name, "my-container");
        assert_eq!(parsed.state, ContainerState::Exited);
        assert_eq!(parsed.command, vec!["echo", "hi"]);
        assert_eq!(parsed.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(parsed.labels.get("app"), Some(&"linpodx".to_string()));
    }
}
