use crate::types::{ContainerId, ImageId, NetworkId, VolumeId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Exited,
    Dead,
    Unknown,
}

impl ContainerState {
    pub fn parse_lossy(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "created" | "configured" => Self::Created,
            "running" => Self::Running,
            "paused" => Self::Paused,
            "exited" | "stopped" => Self::Exited,
            "dead" => Self::Dead,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for ContainerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Exited => "exited",
            Self::Dead => "dead",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSummary {
    pub id: ContainerId,
    #[serde(default)]
    pub names: Vec<String>,
    pub image: String,
    pub state: ContainerState,
    #[serde(default)]
    pub status: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInspect {
    pub id: ContainerId,
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub image_id: Option<ImageId>,
    pub state: ContainerState,
    #[serde(default)]
    pub status: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub mounts: Vec<MountInfo>,
    #[serde(default)]
    pub network_settings: NetworkSettings,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Raw JSON from `podman inspect` for fields the daemon does not (yet) model.
    #[serde(default)]
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountInfo {
    pub source: String,
    pub destination: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSettings {
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

// =========================
// Image resource types
// =========================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSummary {
    pub id: ImageId,
    #[serde(default)]
    pub repo_tags: Vec<String>,
    #[serde(default)]
    pub repo_digests: Vec<String>,
    #[serde(default)]
    pub size_bytes: u64,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInspect {
    pub id: ImageId,
    #[serde(default)]
    pub repo_tags: Vec<String>,
    #[serde(default)]
    pub repo_digests: Vec<String>,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub virtual_size_bytes: u64,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub config: ImageConfig,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub exposed_ports: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
}

// =========================
// Volume resource types
// =========================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSummary {
    pub name: VolumeId,
    pub driver: String,
    pub mountpoint: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInspect {
    pub name: VolumeId,
    pub driver: String,
    pub mountpoint: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub raw: Option<serde_json::Value>,
}

// =========================
// Network resource types
// =========================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub id: NetworkId,
    pub name: String,
    pub driver: String,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInspect {
    pub id: NetworkId,
    pub name: String,
    pub driver: String,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default = "default_true_dns")]
    pub dns_enabled: bool,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub raw: Option<serde_json::Value>,
}

fn default_true_dns() -> bool {
    true
}

// =========================
// Port mapping & volume mount (used by CreateOptions in ipc.rs)
// =========================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    #[default]
    Tcp,
    Udp,
    Sctp,
}

impl fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
        };
        f.write_str(s)
    }
}

impl FromStr for PortProtocol {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "sctp" => Ok(Self::Sctp),
            other => Err(format!("unknown protocol '{other}'")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    #[serde(default)]
    pub protocol: PortProtocol,
    /// Optional bind address on the host (`127.0.0.1`, `0.0.0.0`, IPv6, etc.).
    #[serde(default)]
    pub host_ip: Option<String>,
}

impl PortMapping {
    /// Render as podman `--publish` argument value.
    pub fn to_publish_arg(&self) -> String {
        let suffix = format!(
            "{}:{}/{}",
            self.host_port, self.container_port, self.protocol
        );
        match &self.host_ip {
            Some(ip) => format!("{ip}:{suffix}"),
            None => suffix,
        }
    }

    /// Parse `[host_ip:]host_port:container_port[/proto]`.
    pub fn parse(raw: &str) -> std::result::Result<Self, String> {
        // Split off optional /proto.
        let (head, proto) = match raw.rsplit_once('/') {
            Some((h, p)) => (h, p.parse::<PortProtocol>()?),
            None => (raw, PortProtocol::default()),
        };

        // Now head is `[host_ip:]host_port:container_port`. host_ip can contain colons (IPv6).
        // Strategy: split from the right — last token is container_port, second-to-last is host_port,
        // remainder (if any) is host_ip.
        let mut iter = head.rsplitn(3, ':');
        let cport_str = iter
            .next()
            .ok_or_else(|| format!("missing container port in '{raw}'"))?;
        let hport_str = iter
            .next()
            .ok_or_else(|| format!("missing host port in '{raw}'"))?;
        let host_ip = iter.next().map(str::to_string);

        let container_port: u16 = cport_str
            .parse()
            .map_err(|_| format!("invalid container port '{cport_str}' in '{raw}'"))?;
        let host_port: u16 = hport_str
            .parse()
            .map_err(|_| format!("invalid host port '{hport_str}' in '{raw}'"))?;

        Ok(Self {
            host_port,
            container_port,
            protocol: proto,
            host_ip,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Either a named volume (created via `linpodx volume create`) or an absolute host path.
    pub source: String,
    /// Absolute path inside the container.
    pub destination: String,
    #[serde(default)]
    pub read_only: bool,
}

impl VolumeMount {
    /// Render as podman `--volume` argument value.
    pub fn to_volume_arg(&self) -> String {
        if self.read_only {
            format!("{}:{}:ro", self.source, self.destination)
        } else {
            format!("{}:{}", self.source, self.destination)
        }
    }

    /// Parse `src:dst[:ro]` (or `src:dst:rw`). Multiple-colon paths are not supported in v1.
    pub fn parse(raw: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = raw.splitn(3, ':').collect();
        match parts.as_slice() {
            [src, dst] => Ok(Self {
                source: (*src).to_string(),
                destination: (*dst).to_string(),
                read_only: false,
            }),
            [src, dst, mode] => {
                let read_only = match (*mode).to_ascii_lowercase().as_str() {
                    "ro" => true,
                    "rw" | "" => false,
                    other => {
                        return Err(format!("invalid volume mode '{other}' (expected ro or rw)"))
                    }
                };
                Ok(Self {
                    source: (*src).to_string(),
                    destination: (*dst).to_string(),
                    read_only,
                })
            }
            _ => Err(format!("expected SRC:DST[:ro|rw], got '{raw}'")),
        }
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod resource_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn port_mapping_parse_simple() {
        let p = PortMapping::parse("8080:80").unwrap();
        assert_eq!(p.host_port, 8080);
        assert_eq!(p.container_port, 80);
        assert_eq!(p.protocol, PortProtocol::Tcp);
        assert!(p.host_ip.is_none());
        assert_eq!(p.to_publish_arg(), "8080:80/tcp");
    }

    #[test]
    fn port_mapping_parse_with_proto() {
        let p = PortMapping::parse("53:53/udp").unwrap();
        assert_eq!(p.protocol, PortProtocol::Udp);
        assert_eq!(p.to_publish_arg(), "53:53/udp");
    }

    #[test]
    fn port_mapping_parse_with_host_ip() {
        let p = PortMapping::parse("127.0.0.1:8080:80").unwrap();
        assert_eq!(p.host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(p.host_port, 8080);
        assert_eq!(p.container_port, 80);
        assert_eq!(p.to_publish_arg(), "127.0.0.1:8080:80/tcp");
    }

    #[test]
    fn port_mapping_parse_dynamic_host() {
        let p = PortMapping::parse("0:80").unwrap();
        assert_eq!(p.host_port, 0);
    }

    #[test]
    fn port_mapping_parse_errors() {
        assert!(PortMapping::parse("80").is_err());
        assert!(PortMapping::parse("abc:80").is_err());
        assert!(PortMapping::parse("80:80/quic").is_err());
    }

    #[test]
    fn volume_mount_parse() {
        let v = VolumeMount::parse("data:/var/data").unwrap();
        assert_eq!(v.source, "data");
        assert_eq!(v.destination, "/var/data");
        assert!(!v.read_only);
        assert_eq!(v.to_volume_arg(), "data:/var/data");

        let v_ro = VolumeMount::parse("/host/conf:/etc/conf:ro").unwrap();
        assert!(v_ro.read_only);
        assert_eq!(v_ro.to_volume_arg(), "/host/conf:/etc/conf:ro");

        assert!(VolumeMount::parse("noColon").is_err());
        assert!(VolumeMount::parse("a:b:bad").is_err());
    }

    #[test]
    fn image_summary_serde_roundtrip() {
        let s = ImageSummary {
            id: ImageId::from("sha256:abc"),
            repo_tags: vec!["alpine:latest".into()],
            repo_digests: vec![],
            size_bytes: 5_000_000,
            created: Utc::now(),
            labels: HashMap::new(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: ImageSummary = serde_json::from_str(&j).unwrap();
        assert_eq!(back.repo_tags, s.repo_tags);
        assert_eq!(back.size_bytes, s.size_bytes);
    }

    #[test]
    fn network_inspect_dns_default_true() {
        let v = json!({
            "id": "net123",
            "name": "demo",
            "driver": "bridge",
            "created": "2026-05-09T00:00:00Z"
        });
        let n: NetworkInspect = serde_json::from_value(v).unwrap();
        assert!(n.dns_enabled, "dns_enabled must default to true");
        assert_eq!(n.driver, "bridge");
        assert!(!n.internal);
    }
}
