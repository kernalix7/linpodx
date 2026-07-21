use crate::schema::{NetworkPolicy, SandboxProfile, SourcePattern};
use linpodx_common::approval::ApprovalCategory;
use linpodx_common::ipc::CreateOptions;
use linpodx_common::state::VolumeMount;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Boxed to keep the enum compact — `CreateOptions + AppliedPolicy` is ~470 bytes
    /// while `Deny` is just a String.
    Allow(Box<AllowDecision>),
    Deny {
        reason: String,
    },
    /// One or more violations match the profile's `approval_gates` — caller must consult
    /// the user. The variant carries the gates plus the *would-be* opts (so the manager
    /// can publish them after approval) and the applied snapshot for audit.
    NeedsApproval(Box<NeedsApproval>),
}

#[derive(Debug, Clone)]
pub struct AllowDecision {
    pub opts: CreateOptions,
    pub applied: AppliedPolicy,
}

#[derive(Debug, Clone)]
pub struct NeedsApproval {
    pub gates: Vec<PendingGate>,
    pub opts: CreateOptions,
    pub applied: AppliedPolicy,
}

/// One outstanding gate the manager must run through `ApprovalGateway`.
#[derive(Debug, Clone, Serialize)]
pub struct PendingGate {
    pub category: ApprovalCategory,
    pub payload: serde_json::Value,
}

/// Snapshot of which constraints the profile imposed. Stored in audit log payload so the
/// chain shows what each container was actually run with.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppliedPolicy {
    pub profile_name: String,
    pub network: String,
    pub mounts_allowed: Vec<String>,
    pub cap_drop: Vec<String>,
    pub cap_add: Vec<String>,
    pub read_only_rootfs: bool,
    pub cpus: Option<f32>,
    pub memory_mb: Option<u64>,
    /// Notes about constraints that are recorded but not enforced in v0.1.
    pub deferred: Vec<String>,
}

/// Apply `profile` to `opts`, returning either the transformed opts (Allow), a denial
/// reason (Deny), or a list of gates the caller must clear with `ApprovalGateway`
/// (NeedsApproval).
pub fn apply(profile: &SandboxProfile, mut opts: CreateOptions) -> PolicyDecision {
    let mut deferred: Vec<String> = Vec::new();
    let mut pending_gates: Vec<PendingGate> = Vec::new();
    let gate_mounts = profile
        .approval_gates
        .contains(&ApprovalCategory::MountHostPath);
    let gate_caps = profile.approval_gates.contains(&ApprovalCategory::CapAdd);

    // 1. Mounts whitelist
    let mut mounts_allowed = Vec::new();
    for vm in &mut opts.volumes {
        match mount_verdict(profile, vm) {
            MountVerdict::NotAllowed => {
                if gate_mounts {
                    pending_gates.push(PendingGate {
                        category: ApprovalCategory::MountHostPath,
                        payload: serde_json::json!({
                            "source": vm.source,
                            "destination": vm.destination,
                            "read_only": vm.read_only,
                        }),
                    });
                    // Still record it as "allowed once approved" for audit symmetry.
                    mounts_allowed.push(format!("{}->{} (pending)", vm.source, vm.destination));
                    continue;
                }
                return PolicyDecision::Deny {
                    reason: format!(
                        "mount '{}->{}' is not permitted by profile '{}'",
                        vm.source, vm.destination, profile.name
                    ),
                };
            }
            MountVerdict::DowngradeToReadOnly => {
                // The profile pins this mount read-only but the request asked for
                // read-write. Enforce the profile by downgrading the mount to
                // read-only (mirrors the `read_only_rootfs` force-downgrade in
                // step 4) rather than denying, so the container still runs but
                // with the constraint the profile author intended. The
                // `(ro-enforced)` marker surfaces the override in the audit log.
                vm.read_only = true;
                mounts_allowed.push(format!("{}->{} (ro-enforced)", vm.source, vm.destination));
            }
            MountVerdict::Allowed => {
                mounts_allowed.push(format!("{}->{}", vm.source, vm.destination));
            }
        }
    }

    // 2. Network policy
    let network_label = match &profile.network {
        NetworkPolicy::None => {
            opts.networks = vec!["none".to_string()];
            "none".to_string()
        }
        NetworkPolicy::Allowlist { domains, .. } => {
            deferred.push(format!(
                "network egress allowlist not enforced in v0.1 ({} domains recorded)",
                domains.len()
            ));
            "allowlist".to_string()
        }
        NetworkPolicy::Full => "full".to_string(),
    };

    // 3. Capabilities
    // Merge: profile drops/adds plus any caller-supplied. Caller-supplied caps that aren't
    // in the profile's `capabilities.add` whitelist are gateable when CapAdd is configured.
    let profile_add: HashSet<String> = profile.capabilities.add.iter().cloned().collect();
    for cap in &opts.cap_add {
        if !profile_add.contains(cap) && gate_caps {
            pending_gates.push(PendingGate {
                category: ApprovalCategory::CapAdd,
                payload: serde_json::json!({"cap": cap}),
            });
        }
    }
    let mut drop_set: HashSet<String> = profile.capabilities.drop.iter().cloned().collect();
    drop_set.extend(opts.cap_drop.iter().cloned());
    let mut add_set = profile_add.clone();
    add_set.extend(opts.cap_add.iter().cloned());
    opts.cap_drop = sorted(drop_set);
    opts.cap_add = sorted(add_set);

    // 4. read-only rootfs
    if profile.read_only_rootfs {
        opts.read_only = true;
    }

    // 5. Limits
    if let Some(cpu) = profile.limits.cpu {
        opts.cpus = Some(cpu);
    }
    if let Some(mem) = profile.limits.memory_mb {
        opts.memory_mb = Some(mem);
    }
    if profile.limits.disk_mb.is_some() {
        deferred.push("limits.disk_mb not enforced in v0.1".into());
    }
    if profile.limits.time_secs.is_some() {
        deferred.push("limits.time_secs not enforced in v0.1".into());
    }

    let applied = AppliedPolicy {
        profile_name: profile.name.clone(),
        network: network_label,
        mounts_allowed,
        cap_drop: opts.cap_drop.clone(),
        cap_add: opts.cap_add.clone(),
        read_only_rootfs: opts.read_only,
        cpus: opts.cpus,
        memory_mb: opts.memory_mb,
        deferred,
    };
    if pending_gates.is_empty() {
        PolicyDecision::Allow(Box::new(AllowDecision { opts, applied }))
    } else {
        PolicyDecision::NeedsApproval(Box::new(NeedsApproval {
            gates: pending_gates,
            opts,
            applied,
        }))
    }
}

/// Outcome of matching a requested volume mount against the profile's mount rules.
enum MountVerdict {
    /// No rule matched the source+destination pair — the mount is off-whitelist.
    NotAllowed,
    /// A rule matched and permits the requested access mode as-is.
    Allowed,
    /// A rule matched but pins the mount read-only while the request asked for
    /// read-write. The caller downgrades the mount to read-only to enforce the
    /// profile.
    DowngradeToReadOnly,
}

/// Match `vm` against `profile.mounts`. The first rule whose source+destination
/// matches wins. A matched rule that pins `read_only = true` against a read-write
/// request yields [`MountVerdict::DowngradeToReadOnly`] so the policy engine can
/// force the mount read-only (a matched read-only request, or a read-write rule,
/// is [`MountVerdict::Allowed`]).
fn mount_verdict(profile: &SandboxProfile, vm: &VolumeMount) -> MountVerdict {
    for rule in &profile.mounts {
        let src_match = match &rule.source {
            SourcePattern::Named { name } => vm.source == *name,
            SourcePattern::HostPath { path } => vm.source == *path,
        };
        let dst_match = rule.destination == vm.destination;
        if src_match && dst_match {
            if rule.read_only && !vm.read_only {
                return MountVerdict::DowngradeToReadOnly;
            }
            return MountVerdict::Allowed;
        }
    }
    MountVerdict::NotAllowed
}

fn sorted(set: HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Capabilities, MountRule, SandboxProfile};

    fn empty_profile(name: &str) -> SandboxProfile {
        SandboxProfile {
            version: 1,
            name: name.into(),
            description: String::new(),
            network: NetworkPolicy::Full,
            mounts: vec![],
            limits: Default::default(),
            capabilities: Capabilities {
                drop: vec![],
                add: vec![],
            },
            read_only_rootfs: false,
            approval_gates: vec![],
            approval_timeout_secs: None,
            snapshot_before_run: false,
            passthrough: None,
            distro_kind: None,
            systemd: false,
            snapshot_backend: None,
            syscall_allowlist: None,
            apparmor_extra: None,
            selinux_label: None,
            selinux_type: None,
            auto_encrypt_snapshots: true,
        }
    }

    fn create_opts() -> CreateOptions {
        CreateOptions {
            image: "alpine".into(),
            ..Default::default()
        }
    }

    #[test]
    fn allow_path_no_constraints() {
        let p = empty_profile("loose");
        let decision = apply(&p, create_opts());
        assert!(matches!(decision, PolicyDecision::Allow(_)));
    }

    #[test]
    fn deny_when_mount_not_in_whitelist() {
        let p = empty_profile("strict");
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/etc".into(),
            destination: "/conf".into(),
            read_only: false,
        }];
        let decision = apply(&p, opts);
        match decision {
            PolicyDecision::Deny { reason } => assert!(reason.contains("/etc")),
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn allow_mount_when_in_whitelist() {
        let mut p = empty_profile("with-mount");
        p.mounts.push(MountRule {
            source: SourcePattern::HostPath {
                path: "/etc".into(),
            },
            destination: "/conf".into(),
            read_only: true,
        });
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/etc".into(),
            destination: "/conf".into(),
            read_only: true,
        }];
        let decision = apply(&p, opts);
        assert!(matches!(decision, PolicyDecision::Allow(_)));
    }

    #[test]
    fn ro_rule_downgrades_rw_request_to_read_only() {
        // Profile pins the mount read-only; the request asks for read-write.
        // The engine must enforce RO (downgrade), not silently allow RW.
        let mut p = empty_profile("ro-pin");
        p.mounts.push(MountRule {
            source: SourcePattern::HostPath {
                path: "/data".into(),
            },
            destination: "/data".into(),
            read_only: true,
        });
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/data".into(),
            destination: "/data".into(),
            read_only: false,
        }];
        match apply(&p, opts) {
            PolicyDecision::Allow(d) => {
                assert!(
                    d.opts.volumes[0].read_only,
                    "read-write mount must be forced read-only by the RO rule"
                );
                assert!(d
                    .applied
                    .mounts_allowed
                    .iter()
                    .any(|s| s.contains("ro-enforced")));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn rw_rule_leaves_rw_request_untouched() {
        // Profile allows read-write; the request asks read-write. No downgrade.
        let mut p = empty_profile("rw-ok");
        p.mounts.push(MountRule {
            source: SourcePattern::HostPath {
                path: "/data".into(),
            },
            destination: "/data".into(),
            read_only: false,
        });
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/data".into(),
            destination: "/data".into(),
            read_only: false,
        }];
        match apply(&p, opts) {
            PolicyDecision::Allow(d) => {
                assert!(
                    !d.opts.volumes[0].read_only,
                    "read-write request must stay read-write when the rule permits RW"
                );
                assert!(d
                    .applied
                    .mounts_allowed
                    .iter()
                    .all(|s| !s.contains("ro-enforced")));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn ro_rule_leaves_ro_request_untouched() {
        // Profile pins read-only; request already read-only — allowed, no marker.
        let mut p = empty_profile("ro-ok");
        p.mounts.push(MountRule {
            source: SourcePattern::HostPath {
                path: "/data".into(),
            },
            destination: "/data".into(),
            read_only: true,
        });
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/data".into(),
            destination: "/data".into(),
            read_only: true,
        }];
        match apply(&p, opts) {
            PolicyDecision::Allow(d) => {
                assert!(d.opts.volumes[0].read_only);
                assert!(d
                    .applied
                    .mounts_allowed
                    .iter()
                    .all(|s| !s.contains("ro-enforced")));
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn network_none_translates_to_none_arg() {
        let mut p = empty_profile("netless");
        p.network = NetworkPolicy::None;
        if let PolicyDecision::Allow(d) = apply(&p, create_opts()) {
            assert_eq!(d.opts.networks, vec!["none"]);
        } else {
            panic!("expected Allow");
        }
    }

    #[test]
    fn cap_drop_all_with_explicit_add() {
        let mut p = empty_profile("caps");
        p.capabilities = Capabilities {
            drop: vec!["ALL".into()],
            add: vec!["NET_BIND_SERVICE".into(), "SETUID".into()],
        };
        if let PolicyDecision::Allow(d) = apply(&p, create_opts()) {
            assert_eq!(d.opts.cap_drop, vec!["ALL"]);
            assert!(d.opts.cap_add.contains(&"NET_BIND_SERVICE".to_string()));
            assert!(d.opts.cap_add.contains(&"SETUID".to_string()));
            assert_eq!(d.applied.cap_drop, vec!["ALL"]);
        } else {
            panic!("expected Allow");
        }
    }

    #[test]
    fn limits_translate_to_create_opts() {
        let mut p = empty_profile("limited");
        p.limits.cpu = Some(0.5);
        p.limits.memory_mb = Some(256);
        p.limits.disk_mb = Some(1024); // recorded only
        p.read_only_rootfs = true;
        if let PolicyDecision::Allow(d) = apply(&p, create_opts()) {
            assert_eq!(d.opts.cpus, Some(0.5));
            assert_eq!(d.opts.memory_mb, Some(256));
            assert!(d.opts.read_only);
            assert!(d.applied.deferred.iter().any(|s| s.contains("disk_mb")));
        } else {
            panic!("expected Allow");
        }
    }

    #[test]
    fn mount_violation_with_gate_returns_needs_approval() {
        let mut p = empty_profile("gated");
        p.approval_gates = vec![ApprovalCategory::MountHostPath];
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/etc".into(),
            destination: "/conf".into(),
            read_only: false,
        }];
        let decision = apply(&p, opts);
        match decision {
            PolicyDecision::NeedsApproval(d) => {
                assert_eq!(d.gates.len(), 1);
                assert_eq!(d.gates[0].category, ApprovalCategory::MountHostPath);
                assert_eq!(
                    d.gates[0].payload.get("source").and_then(|v| v.as_str()),
                    Some("/etc")
                );
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn cap_add_violation_with_gate_returns_needs_approval() {
        let mut p = empty_profile("cap-gated");
        p.approval_gates = vec![ApprovalCategory::CapAdd];
        // Profile.capabilities.add is empty, so any cap_add is "extra".
        let mut opts = create_opts();
        opts.cap_add = vec!["NET_BIND_SERVICE".into()];
        let decision = apply(&p, opts);
        match decision {
            PolicyDecision::NeedsApproval(d) => {
                assert_eq!(d.gates.len(), 1);
                assert_eq!(d.gates[0].category, ApprovalCategory::CapAdd);
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn empty_approval_gates_preserves_phase_1c_deny_behavior() {
        // No approval_gates configured → mount violation = immediate Deny.
        let p = empty_profile("strict-1c");
        let mut opts = create_opts();
        opts.volumes = vec![VolumeMount {
            source: "/etc".into(),
            destination: "/conf".into(),
            read_only: false,
        }];
        assert!(matches!(apply(&p, opts), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn allowlist_network_records_deferral() {
        let mut p = empty_profile("egress");
        p.network = NetworkPolicy::Allowlist {
            domains: vec!["api.openai.com".into()],
            l4_rules: vec![],
        };
        if let PolicyDecision::Allow(d) = apply(&p, create_opts()) {
            assert!(d
                .applied
                .deferred
                .iter()
                .any(|s| s.contains("egress allowlist")));
        } else {
            panic!("expected Allow");
        }
    }
}
