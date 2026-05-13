use linpodx_common::approval::ApprovalCategory;
use linpodx_common::network::EgressRule;
use linpodx_common::passthrough::{DistroKind, PassthroughSpec, SnapshotBackendKind};
use serde::{Deserialize, Serialize};

/// Currently supported profile schema version.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// Schema version. Must equal `PROFILE_SCHEMA_VERSION` (= 1) for now.
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Network policy. Defaults to `none` (most restrictive).
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Allowed mounts. Container `--volume` arguments not matching any rule are rejected.
    #[serde(default)]
    pub mounts: Vec<MountRule>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub capabilities: Capabilities,
    /// If true, container is run with `--read-only` rootfs.
    #[serde(default)]
    pub read_only_rootfs: bool,
    // ----- Phase 2A: approval gates -----
    /// Categories that should prompt the user for approval instead of immediate deny when
    /// a violation is detected. Empty (default) preserves Phase 1C behaviour.
    #[serde(default)]
    pub approval_gates: Vec<ApprovalCategory>,
    /// Override the global default approval timeout (30 s) for this profile.
    #[serde(default)]
    pub approval_timeout_secs: Option<u64>,
    // ----- Phase 2B: snapshot integration -----
    /// If true, the sandbox manager takes a snapshot of the container before starting it
    /// so the user can roll back. Recorded with label `pre-run-<unix-ms>`.
    #[serde(default)]
    pub snapshot_before_run: bool,
    // ----- Phase 3: GUI / desktop passthrough -----
    /// Per-profile passthrough grants. The daemon merges these with any
    /// `CreateOptions.passthrough` overrides at create time.
    #[serde(default)]
    pub passthrough: Option<PassthroughSpec>,
    // ----- Phase 4: multi-distro defaults -----
    /// If set, the profile is associated with a specific distro template. Used by the
    /// distro manager to pick install hooks and the default shell.
    #[serde(default)]
    pub distro_kind: Option<DistroKind>,
    /// Run the container with `--systemd=true`. Requires the base image to have systemd
    /// (or a compatible PID 1) and a cgroup-v2 host.
    #[serde(default)]
    pub systemd: bool,
    // ----- Phase 7: pluggable snapshot backend -----
    /// Override the daemon's default `SnapshotBackendKind` for snapshots taken under
    /// this profile. `None` defers to the global default (PodmanCommit).
    #[serde(default)]
    pub snapshot_backend: Option<SnapshotBackendKind>,
    // ----- Phase 11: seccomp / AppArmor profile generation -----
    /// Optional seccomp syscall allowlist. When `Some`, the secprofile compiler
    /// produces a custom seccomp BPF JSON that the daemon passes to podman as
    /// `--security-opt seccomp=<file>`. When `None`, podman's default seccomp
    /// profile is used.
    #[serde(default)]
    pub syscall_allowlist: Option<Vec<String>>,
    /// Optional AppArmor profile extras. When `Some`, the secprofile compiler
    /// generates an AppArmor profile text and registers it via `apparmor_parser -r`.
    #[serde(default)]
    pub apparmor_extra: Option<AppArmorExtras>,
    // ----- Phase 12: SELinux -----
    /// When `Some`, applied verbatim as `--security-opt label=type:<value>` to
    /// `podman create`. Use for fixed system labels (e.g. "container_t").
    #[serde(default)]
    pub selinux_label: Option<String>,
    /// When `Some`, the secprofile compiler synthesizes a SELinux module .te file
    /// for the named domain, runs `checkmodule + semodule_package + semodule -i`,
    /// and applies `--security-opt label=type:<selinux_type>` at run time.
    #[serde(default)]
    pub selinux_type: Option<String>,
    // ----- Phase 17 Stream B: snapshot encryption auto-trigger -----
    /// When `true` (default), commit-snapshot events fired under this profile route
    /// through `AutoEncryptHook` and trigger `runtime_snapshot::encrypt_committed_image`
    /// when daemon-level encryption is configured. Set to `false` to keep snapshots
    /// taken under this profile in plaintext even when global encryption is enabled.
    #[serde(default = "default_auto_encrypt_snapshots")]
    pub auto_encrypt_snapshots: bool,
}

fn default_auto_encrypt_snapshots() -> bool {
    true
}

/// Phase 11: extra AppArmor rules layered on top of the auto-derived defaults
/// (mounts/network/capabilities → file/network/cap rules).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppArmorExtras {
    /// Additional `deny` rules to append to the generated profile.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Additional `allow` rules to append.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// `--network none` enforced. Default — strictest.
    #[default]
    None,
    /// Egress allowlist of hostnames / CIDRs.
    /// `domains` is the DNS-only filter applied by the daemon's in-process DNS proxy
    /// (Phase 2E). `l4_rules` is the privileged L4 firewall enforced by the optional
    /// `linpodx-netfilter-helper` binary inside the container's network namespace
    /// (Phase 5) — when the helper isn't installed the L4 layer is skipped with a warn
    /// and the DNS filter alone applies.
    Allowlist {
        #[serde(default)]
        domains: Vec<String>,
        #[serde(default)]
        l4_rules: Vec<EgressRule>,
    },
    /// No constraint — host networking semantics depend on user-supplied `--network`.
    Full,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountRule {
    pub source: SourcePattern,
    pub destination: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourcePattern {
    /// Named volume (created via `linpodx volume create`).
    Named { name: String },
    /// Absolute host path. Exact match in v0.1 (no glob/regex).
    HostPath { path: String },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// CPU shares as a fraction (e.g. 1.5 = 1.5 cores). Translates to `--cpus`.
    pub cpu: Option<f32>,
    /// Memory cap in MiB. Translates to `--memory <N>m`.
    pub memory_mb: Option<u64>,
    /// Disk quota in MiB. **Recorded only in v0.1** — Phase 2 wires it through.
    pub disk_mb: Option<u64>,
    /// Wall-clock execution time cap in seconds. **Recorded only in v0.1**.
    pub time_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Capabilities to drop. Default: all (`["ALL"]`) — strictest.
    #[serde(default = "default_drop")]
    pub drop: Vec<String>,
    /// Capabilities to add back after dropping.
    #[serde(default)]
    pub add: Vec<String>,
}

fn default_drop() -> Vec<String> {
    vec!["ALL".to_string()]
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            drop: default_drop(),
            add: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_yaml() -> &'static str {
        r#"
version: 1
name: ai-agent
description: Sandbox profile for a shell-running AI agent
network:
  kind: none
mounts:
  - source:
      kind: named
      name: workspace
    destination: /workspace
    read_only: false
  - source:
      kind: host_path
      path: /home/me/notes
    destination: /notes
    read_only: true
limits:
  cpu: 2.0
  memory_mb: 1024
capabilities:
  drop: ["ALL"]
  add: ["NET_BIND_SERVICE"]
read_only_rootfs: true
"#
    }

    #[test]
    fn yaml_roundtrip() {
        let parsed: SandboxProfile = serde_yml::from_str(sample_yaml()).expect("parse");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.name, "ai-agent");
        assert!(parsed.read_only_rootfs);
        assert_eq!(parsed.limits.memory_mb, Some(1024));
        assert_eq!(parsed.capabilities.drop, vec!["ALL"]);
        assert_eq!(parsed.capabilities.add, vec!["NET_BIND_SERVICE"]);
        assert_eq!(parsed.mounts.len(), 2);
        let serialized = serde_yml::to_string(&parsed).unwrap();
        let reparsed: SandboxProfile = serde_yml::from_str(&serialized).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn defaults_to_strictest_network_and_caps() {
        let yaml = "version: 1\nname: minimal";
        let parsed: SandboxProfile = serde_yml::from_str(yaml).expect("parse minimal");
        assert!(matches!(parsed.network, NetworkPolicy::None));
        assert_eq!(parsed.capabilities.drop, vec!["ALL"]);
        assert!(parsed.capabilities.add.is_empty());
        assert!(!parsed.read_only_rootfs);
    }

    #[test]
    fn allowlist_network_parses() {
        let yaml = r#"
version: 1
name: net-allow
network:
  kind: allowlist
  domains: [api.example.com, registry.example.com]
"#;
        let parsed: SandboxProfile = serde_yml::from_str(yaml).expect("parse");
        match parsed.network {
            NetworkPolicy::Allowlist { domains, l4_rules } => {
                assert_eq!(domains.len(), 2);
                assert!(domains.contains(&"api.example.com".to_string()));
                assert!(l4_rules.is_empty());
            }
            _ => panic!("expected Allowlist"),
        }
    }
}
