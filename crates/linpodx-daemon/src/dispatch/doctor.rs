//! Phase 18 Stream C — doctor check helpers. Each `check_*` returns a
//! [`responses::DoctorCheck`] with a stable id, label, outcome, optional
//! `detail` (human-readable status detail), and optional `fix_hint`.
//!
//! Helpers are deliberately small + side-effect free (read env / fs / spawn
//! short-lived subprocesses) so the whole `run_doctor` pass is deterministic
//! from the user's environment alone.

use linpodx_common::ipc::responses::{DoctorCheck, DoctorOutcome};
use std::path::PathBuf;
use tokio::process::Command;

fn ok(id: &str, label: &str, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        id: id.to_string(),
        label: label.to_string(),
        outcome: DoctorOutcome::Pass,
        detail: Some(detail.into()),
        fix_hint: None,
    }
}

fn warn(id: &str, label: &str, detail: impl Into<String>, hint: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        id: id.to_string(),
        label: label.to_string(),
        outcome: DoctorOutcome::Warn,
        detail: Some(detail.into()),
        fix_hint: Some(hint.into()),
    }
}

fn fail(id: &str, label: &str, detail: impl Into<String>, hint: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        id: id.to_string(),
        label: label.to_string(),
        outcome: DoctorOutcome::Fail,
        detail: Some(detail.into()),
        fix_hint: Some(hint.into()),
    }
}

/// Parse `Podman 4.9.4` or `podman version 4.9.4` into `(4, 9, 4)`. Returns
/// `None` when no `MAJOR.MINOR[.PATCH]` triple is found. Public for unit
/// testing.
pub(super) fn parse_podman_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut major = None;
    for token in s.split_whitespace() {
        // Strip leading "v" if any.
        let token = token.strip_prefix('v').unwrap_or(token);
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        let a = parts[0].parse::<u32>().ok();
        let b = parts[1].parse::<u32>().ok();
        let c = parts.get(2).and_then(|p| {
            // The third component might have a `-rc1` / `-dev` suffix.
            let head: String = p.chars().take_while(|ch| ch.is_ascii_digit()).collect();
            head.parse::<u32>().ok()
        });
        if let (Some(a), Some(b)) = (a, b) {
            major = Some((a, b, c.unwrap_or(0)));
            break;
        }
    }
    major
}

/// Compare a parsed version against the minimum supported `(4, 6, 0)`.
pub(super) fn is_supported_podman(v: (u32, u32, u32)) -> bool {
    v >= (4, 6, 0)
}

/// Run both `podman-installed` and `podman-version` in a single subprocess
/// invocation. Returns `(installed_check, version_check)` so the dispatcher
/// can push both onto the report. Splitting these into two stable ids lets
/// external monitoring tools alert separately on "podman missing" vs
/// "podman too old".
pub(super) async fn check_podman_binary_and_version(
    bin: &str,
    cached: &str,
) -> (DoctorCheck, DoctorCheck) {
    let installed_id = "podman-installed";
    let installed_label = "podman binary";
    let version_id = "podman-version";
    let version_label = "podman version (>= 4.6.0)";

    // Prefer the cached version captured by `PodmanConfig::probe_version`
    // at daemon startup. Fall back to running `podman --version` if the
    // cache is empty (e.g. older daemons without the probe step).
    let probed = if cached.trim().is_empty() {
        match Command::new(bin).arg("--version").output().await {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            Ok(_) => String::new(),
            Err(_) => {
                let fail_installed = fail(
                    installed_id,
                    installed_label,
                    format!("`{bin}` not found on PATH"),
                    "install podman: `sudo dnf install podman` (Fedora/RHEL) or \
                     `sudo apt install podman` (Debian/Ubuntu). See docs/INSTALL.md#podman",
                );
                let fail_version = fail(
                    version_id,
                    version_label,
                    "podman binary missing — version unknown",
                    "see docs/INSTALL.md#podman",
                );
                return (fail_installed, fail_version);
            }
        }
    } else {
        cached.to_string()
    };

    let installed = ok(installed_id, installed_label, format!("found `{bin}`"));

    let Some(version) = parse_podman_version(&probed) else {
        let version_check = warn(
            version_id,
            version_label,
            format!("could not parse podman version from `{probed}`"),
            "verify `podman --version` outputs `Podman MAJOR.MINOR.PATCH` and re-run doctor",
        );
        return (installed, version_check);
    };

    let version_check = if is_supported_podman(version) {
        ok(
            version_id,
            version_label,
            format!(
                "podman {}.{}.{} (>= 4.6.0)",
                version.0, version.1, version.2
            ),
        )
    } else {
        fail(
            version_id,
            version_label,
            format!(
                "podman {}.{}.{} is older than the supported minimum 4.6.0",
                version.0, version.1, version.2
            ),
            "upgrade podman: `sudo dnf upgrade podman` or \
             `sudo apt install -t backports podman`. See docs/INSTALL.md#podman",
        )
    };

    (installed, version_check)
}

pub(super) async fn check_rootless_setup(bin: &str) -> DoctorCheck {
    let id = "rootless-setup";
    let label = "podman rootless mode";
    let result = Command::new(bin)
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .output()
        .await;
    match result {
        Ok(out) if out.status.success() => {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            match val.as_str() {
                "true" => ok(id, label, "rootless mode enabled"),
                "false" => warn(
                    id,
                    label,
                    "podman is running as root (rootful)",
                    "linpodx prefers rootless: run as a non-root user, or accept the \
                     reduced sandboxing posture",
                ),
                other => warn(
                    id,
                    label,
                    format!("podman info returned unexpected value `{other}`"),
                    "ensure podman 4.6+ supports the `Host.Security.Rootless` field",
                ),
            }
        }
        Ok(out) => warn(
            id,
            label,
            format!(
                "podman info exited with status {}",
                out.status.code().unwrap_or(-1)
            ),
            "run `podman info` manually to inspect the failure",
        ),
        Err(e) => warn(
            id,
            label,
            format!("could not run podman info: {e}"),
            "ensure the podman binary is on PATH and re-run doctor",
        ),
    }
}

/// cgroup v2 is required for podman's rootless lifecycle on modern kernels.
/// The reliable indicator is the presence of `/sys/fs/cgroup/cgroup.controllers`
/// — only the unified hierarchy mounts that file at the root.
pub(super) fn check_cgroup_v2() -> DoctorCheck {
    let id = "cgroup-v2-available";
    let label = "cgroup v2 (unified hierarchy)";
    let marker = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers");
    if marker.exists() {
        match std::fs::read_to_string(marker) {
            Ok(content) => {
                let controllers = content.trim();
                if controllers.is_empty() {
                    warn(
                        id,
                        label,
                        "cgroup v2 mounted but no controllers exposed",
                        "delegate controllers to your user with systemd's `Delegate=yes`. \
                         See docs/INSTALL.md#cgroup-v2",
                    )
                } else {
                    ok(id, label, format!("controllers: {controllers}"))
                }
            }
            Err(e) => warn(
                id,
                label,
                format!("could not read /sys/fs/cgroup/cgroup.controllers: {e}"),
                "verify kernel exports the unified hierarchy. See docs/INSTALL.md#cgroup-v2",
            ),
        }
    } else {
        fail(
            id,
            label,
            "no /sys/fs/cgroup/cgroup.controllers — running on cgroup v1",
            "boot with `systemd.unified_cgroup_hierarchy=1` (set in kernel cmdline) and \
             reboot. See docs/INSTALL.md#cgroup-v2",
        )
    }
}

/// Rootless containers only get resource *stats* for controllers systemd
/// delegates to the user service. Distros commonly delegate just `pids`, in
/// which case `memory.current` never exists inside container scopes and every
/// memory reading (podman's and ours) is a silent 0 — CPU% still works because
/// it isn't derived from the missing controller. Surfacing this here turns an
/// invisible all-zeros dashboard into an actionable host fix.
pub(super) fn check_cgroup_delegation() -> DoctorCheck {
    let id = "cgroup-delegation";
    let label = "cgroup controller delegation (rootless stats)";
    let uid = unsafe_free_uid();
    let path =
        format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers");
    match std::fs::read_to_string(&path) {
        Ok(content) => delegation_check_from(id, label, &content),
        Err(_) => warn(
            id,
            label,
            format!("could not read {path} (non-systemd session or system-level podman?)"),
            "if running rootless under systemd, verify controller delegation; otherwise this \
             check does not apply",
        ),
    }
}

/// Classify a `cgroup.controllers` line: pass when both `memory` and `cpu`
/// are delegated, warn (with the systemd remediation) otherwise.
fn delegation_check_from(id: &str, label: &str, content: &str) -> DoctorCheck {
    let controllers: Vec<&str> = content.split_whitespace().collect();
    let missing: Vec<&str> = ["memory", "cpu"]
        .iter()
        .copied()
        .filter(|c| !controllers.contains(c))
        .collect();
    if missing.is_empty() {
        ok(id, label, format!("delegated: {}", content.trim()))
    } else {
        warn(
            id,
            label,
            format!(
                "user service delegates only [{}] — missing [{}]; container memory/cpu \
                 stats will read 0",
                controllers.join(" "),
                missing.join(" ")
            ),
            "create /etc/systemd/system/user@.service.d/delegate.conf with \
             `[Service]\\nDelegate=cpu cpuset io memory pids`, run \
             `systemctl daemon-reload`, then log out and back in and restart \
             your containers",
        )
    }
}

/// `getuid()` without libc: `/proc/self` is owned by the process uid.
fn unsafe_free_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or(1000)
}

/// Confirm the daemon's Unix socket exists, is a socket, and is mode 0700
/// (or stricter) — the daemon's `server.rs` enforces 0700 on bind.
pub(super) fn check_socket_permissions() -> DoctorCheck {
    let id = "socket-permissions";
    let label = "daemon Unix socket";
    let path = default_socket_path();
    match std::fs::metadata(&path) {
        Ok(meta) => {
            use std::os::unix::fs::{FileTypeExt, PermissionsExt};
            if !meta.file_type().is_socket() {
                return fail(
                    id,
                    label,
                    format!("{} exists but is not a Unix socket", path.display()),
                    "remove the stale file and restart `linpodx daemon start`. \
                     See docs/INSTALL.md#daemon",
                );
            }
            let mode = meta.permissions().mode() & 0o777;
            // Anything that is not group/other writable (i.e. low bits 0o022 absent)
            // is acceptable for a per-user runtime socket.
            if mode & 0o077 == 0 {
                ok(
                    id,
                    label,
                    format!("{} (mode 0{:o}, listening)", path.display(), mode),
                )
            } else {
                warn(
                    id,
                    label,
                    format!("{} has loose mode 0{:o}", path.display(), mode),
                    format!(
                        "tighten with `chmod 0700 {}` or restart the daemon to re-bind",
                        path.display()
                    ),
                )
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => warn(
            id,
            label,
            format!("no socket at {}", path.display()),
            "start the daemon: `linpodx daemon start`. See docs/INSTALL.md#daemon",
        ),
        Err(e) => warn(
            id,
            label,
            format!("could not stat {}: {e}", path.display()),
            "check filesystem permissions on the runtime directory",
        ),
    }
}

/// `${XDG_CONFIG_HOME:-~/.config}/linpodx/profiles` — the sandbox profile
/// directory that `SandboxManager` reads YAML from. Absent → warn (the
/// daemon will create it on first use) but the user has no profiles yet.
pub(super) fn check_sandbox_profile_dir() -> DoctorCheck {
    let id = "sandbox-profile-dir";
    let label = "sandbox profile directory";
    let dir = default_config_dir().join("profiles");
    check_dir_presence(id, label, &dir, "sandbox-profiles")
}

/// `${XDG_CONFIG_HOME:-~/.config}/linpodx/mcp` — where users drop custom
/// MCP bridge policy files. Same warn-only semantics as the profile dir.
pub(super) fn check_mcp_bridge_dir() -> DoctorCheck {
    let id = "mcp-bridge-dir";
    let label = "MCP bridge config directory";
    let dir = default_config_dir().join("mcp");
    check_dir_presence(id, label, &dir, "mcp-bridge")
}

/// Shared implementation for the two config-directory checks. Returns
/// `Pass` when the directory exists + is writable, `Warn` when missing
/// (daemon recreates it), `Fail` when it exists but is not a directory or
/// is not writable.
fn check_dir_presence(
    id: &'static str,
    label: &'static str,
    dir: &std::path::Path,
    docs_anchor: &str,
) -> DoctorCheck {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            let marker = dir.join(".linpodx-doctor-probe");
            match std::fs::write(&marker, b"") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&marker);
                    ok(id, label, format!("{} (writable)", dir.display()))
                }
                Err(e) => fail(
                    id,
                    label,
                    format!("{} exists but is not writable: {e}", dir.display()),
                    format!(
                        "fix permissions: `chmod u+rwx {}`. See docs/INSTALL.md#{docs_anchor}",
                        dir.display()
                    ),
                ),
            }
        }
        Ok(_) => fail(
            id,
            label,
            format!("{} exists but is not a directory", dir.display()),
            format!(
                "remove the file and let the daemon recreate the directory. \
                 See docs/INSTALL.md#{docs_anchor}"
            ),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => warn(
            id,
            label,
            format!("{} does not exist", dir.display()),
            format!(
                "created on first daemon start; or `mkdir -p {}`. \
                 See docs/INSTALL.md#{docs_anchor}",
                dir.display()
            ),
        ),
        Err(e) => fail(
            id,
            label,
            format!("could not stat {}: {e}", dir.display()),
            "check that $XDG_CONFIG_HOME or $HOME points to a readable location",
        ),
    }
}

pub(super) fn check_display_session() -> DoctorCheck {
    let id = "display-session";
    let label = "graphical display session";
    let session_type = std::env::var("XDG_SESSION_TYPE").ok();
    let wayland = std::env::var("WAYLAND_DISPLAY").ok();
    let x11 = std::env::var("DISPLAY").ok();

    match (session_type.as_deref(), wayland.as_deref(), x11.as_deref()) {
        (Some("wayland"), Some(w), _) => ok(id, label, format!("wayland (WAYLAND_DISPLAY={w})")),
        (Some("x11"), _, Some(d)) => ok(id, label, format!("x11 (DISPLAY={d})")),
        (_, Some(w), _) => ok(id, label, format!("wayland (WAYLAND_DISPLAY={w})")),
        (_, _, Some(d)) => ok(id, label, format!("x11 (DISPLAY={d})")),
        _ => warn(
            id,
            label,
            "no Wayland/X11 environment detected",
            "GUI passthrough containers will be unavailable; headless containers still work. \
             set XDG_SESSION_TYPE / WAYLAND_DISPLAY / DISPLAY in your shell rc to enable.",
        ),
    }
}

pub(super) fn check_selinux() -> DoctorCheck {
    let id = "selinux-mode";
    let label = "SELinux mode";
    match std::fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(contents) => match contents.trim() {
            "0" => ok(id, label, "permissive"),
            "1" => ok(id, label, "enforcing"),
            other => warn(
                id,
                label,
                format!("/sys/fs/selinux/enforce returned `{other}`"),
                "investigate the SELinux subsystem; expected `0` (permissive) or `1` (enforcing)",
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ok(id, label, "disabled (no /sys/fs/selinux/enforce)")
        }
        Err(e) => warn(
            id,
            label,
            format!("could not read /sys/fs/selinux/enforce: {e}"),
            "check kernel SELinux config; doctor falls back to permissive assumption",
        ),
    }
}

pub(super) async fn check_netfilter_helper() -> DoctorCheck {
    let id = "netfilter-helper";
    let label = "linpodx-netfilter-helper capabilities";
    // The helper binary is typically installed alongside the daemon. Try a
    // small list of well-known locations.
    let candidates = [
        "/usr/local/libexec/linpodx-netfilter-helper",
        "/usr/libexec/linpodx-netfilter-helper",
        "/usr/local/bin/linpodx-netfilter-helper",
        "/usr/bin/linpodx-netfilter-helper",
    ];
    let helper = candidates.iter().find(|p| std::path::Path::new(p).exists());
    let Some(helper) = helper else {
        return warn(
            id,
            label,
            "helper binary not installed",
            "L4 egress firewall will be disabled. install via the linpodx package or \
             run `sudo install -m 0755 target/release/linpodx-netfilter-helper \
             /usr/local/libexec/`",
        );
    };

    let out = Command::new("getcap").arg(helper).output().await;
    let parsed = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(o) => {
            return warn(
                id,
                label,
                format!(
                    "getcap exited with status {}: {}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                "install libcap-progs (`sudo dnf install libcap` / `sudo apt install libcap2-bin`)",
            );
        }
        Err(e) => {
            return warn(
                id,
                label,
                format!("could not run getcap: {e}"),
                "install libcap-progs / libcap2-bin and re-run doctor",
            );
        }
    };

    if parsed.contains("cap_net_admin") {
        ok(id, label, format!("{helper} has cap_net_admin"))
    } else {
        fail(
            id,
            label,
            format!("{helper} is missing cap_net_admin"),
            format!("grant the capability: `sudo setcap cap_net_admin,cap_sys_admin+ep {helper}`"),
        )
    }
}

pub(super) async fn check_system_libs() -> DoctorCheck {
    let id = "system-libs";
    let label = "GUI passthrough libraries";
    let probes = [
        (
            "libwayland-client.so.0",
            "libwayland-client0 (Debian/Ubuntu) / wayland-libs-client (Fedora)",
        ),
        ("libX11.so.6", "libx11-6 / libX11"),
        ("libpipewire-0.3.so.0", "libpipewire-0.3-0 / pipewire-libs"),
        ("libpulse.so.0", "libpulse0 / pulseaudio-libs"),
        ("libdbus-1.so.3", "libdbus-1-3 / dbus-libs"),
    ];

    let out = Command::new("ldconfig").arg("-p").output().await;
    let cache = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(o) => {
            return warn(
                id,
                label,
                format!(
                    "ldconfig exited with status {}",
                    o.status.code().unwrap_or(-1)
                ),
                "install glibc-common (`sudo dnf install glibc-common` / `sudo apt install libc-bin`)",
            );
        }
        Err(e) => {
            return warn(
                id,
                label,
                format!("could not run ldconfig: {e}"),
                "install libc-bin / glibc-common and re-run doctor",
            );
        }
    };

    let mut missing: Vec<(&str, &str)> = Vec::new();
    for (lib, pkg) in probes.iter() {
        if !cache.contains(lib) {
            missing.push((lib, pkg));
        }
    }

    if missing.is_empty() {
        ok(
            id,
            label,
            format!("all {} GUI passthrough libs present", probes.len()),
        )
    } else {
        let names: Vec<String> = missing.iter().map(|(l, _)| (*l).to_string()).collect();
        let hint = missing
            .iter()
            .map(|(l, p)| format!("{l} → install {p}"))
            .collect::<Vec<_>>()
            .join("; ");
        warn(id, label, format!("missing: {}", names.join(", ")), hint)
    }
}

/// Mirror of [`crate::config::DaemonConfig::resolved_socket`] — kept in
/// sync so doctor can probe the socket without injecting the config. The
/// daemon's runtime listener uses the same defaults.
fn default_socket_path() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("linpodx.sock");
        }
    }
    let uid = nix_geteuid();
    PathBuf::from(format!("/tmp/linpodx-{uid}.sock"))
}

/// Mirror of `$XDG_CONFIG_HOME/linpodx` (fallback `~/.config/linpodx`).
/// Sandbox profiles and MCP bridge configs both live under this root.
fn default_config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("linpodx");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("linpodx")
}

/// Read the effective UID via `/proc/self/loginuid` fallback `/proc/self/status`
/// — avoids pulling in the `nix` crate just for `geteuid()`. The daemon
/// already has `forbid(unsafe_code)`, so `libc::geteuid()` is off the table.
fn nix_geteuid() -> u32 {
    // `/proc/self/loginuid` may be `4294967295` (no login uid). Prefer
    // `/proc/self/status` which always has the real Uid line.
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                if let Some(first) = rest.split_whitespace().next() {
                    if let Ok(uid) = first.parse::<u32>() {
                        return uid;
                    }
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_podman_basic() {
        assert_eq!(parse_podman_version("Podman 4.9.4"), Some((4, 9, 4)));
        assert_eq!(
            parse_podman_version("podman version 5.0.0"),
            Some((5, 0, 0))
        );
        assert_eq!(parse_podman_version("podman 4.6"), Some((4, 6, 0)));
        assert_eq!(
            parse_podman_version("podman 5.1.0-rc1"),
            Some((5, 1, 0)),
            "rc suffix on patch component should be stripped"
        );
    }

    #[test]
    fn parse_podman_none_when_absent() {
        assert_eq!(parse_podman_version("hello world"), None);
        assert_eq!(parse_podman_version(""), None);
    }

    #[test]
    fn supported_version_threshold() {
        assert!(is_supported_podman((4, 6, 0)));
        assert!(is_supported_podman((4, 9, 4)));
        assert!(is_supported_podman((5, 0, 0)));
        assert!(!is_supported_podman((4, 5, 9)));
        assert!(!is_supported_podman((3, 9, 0)));
    }

    #[test]
    fn delegation_full_set_passes() {
        let c = delegation_check_from("cgroup-delegation", "l", "cpuset cpu io memory pids");
        assert_eq!(c.outcome, DoctorOutcome::Pass);
    }

    #[test]
    fn delegation_pids_only_warns_with_remediation() {
        let c = delegation_check_from("cgroup-delegation", "l", "pids");
        assert_eq!(c.outcome, DoctorOutcome::Warn);
        assert!(c
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("missing [memory cpu]"));
        assert!(c
            .fix_hint
            .as_deref()
            .unwrap_or("")
            .contains("delegate.conf"));
    }

    #[test]
    fn delegation_memory_only_missing_cpu_warns() {
        let c = delegation_check_from("cgroup-delegation", "l", "memory pids");
        assert_eq!(c.outcome, DoctorOutcome::Warn);
        assert!(c.detail.as_deref().unwrap_or("").contains("missing [cpu]"));
    }

    #[test]
    fn ok_warn_fail_constructors_set_outcome() {
        let c = ok("a", "b", "c");
        assert_eq!(c.outcome, DoctorOutcome::Pass);
        assert!(c.fix_hint.is_none());

        let c = warn("a", "b", "c", "fix");
        assert_eq!(c.outcome, DoctorOutcome::Warn);
        assert_eq!(c.fix_hint.as_deref(), Some("fix"));

        let c = fail("a", "b", "c", "fix");
        assert_eq!(c.outcome, DoctorOutcome::Fail);
        assert_eq!(c.fix_hint.as_deref(), Some("fix"));
    }

    #[test]
    fn display_session_wayland_pref() {
        // We cannot reliably mutate process env in parallel tests; instead
        // verify the function returns *something* with a stable id.
        let c = check_display_session();
        assert_eq!(c.id, "display-session");
    }

    #[test]
    fn selinux_check_stable_id() {
        let c = check_selinux();
        assert_eq!(c.id, "selinux-mode");
        // Always one of the three outcomes — no panics on absent /sys/fs/selinux.
        assert!(matches!(
            c.outcome,
            DoctorOutcome::Pass | DoctorOutcome::Warn | DoctorOutcome::Fail
        ));
    }

    #[test]
    fn socket_permissions_check_stable_id() {
        let c = check_socket_permissions();
        assert_eq!(c.id, "socket-permissions");
    }

    #[test]
    fn cgroup_v2_check_stable_id() {
        let c = check_cgroup_v2();
        assert_eq!(c.id, "cgroup-v2-available");
        // Outcome depends on the host kernel; just sanity-check the enum
        // discriminant rather than asserting pass/fail.
        assert!(matches!(
            c.outcome,
            DoctorOutcome::Pass | DoctorOutcome::Warn | DoctorOutcome::Fail
        ));
    }

    #[test]
    fn sandbox_profile_dir_stable_id() {
        let c = check_sandbox_profile_dir();
        assert_eq!(c.id, "sandbox-profile-dir");
    }

    #[test]
    fn mcp_bridge_dir_stable_id() {
        let c = check_mcp_bridge_dir();
        assert_eq!(c.id, "mcp-bridge-dir");
    }

    #[test]
    fn default_socket_path_uses_xdg_runtime() {
        let prev = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/linpodx-doctor-test");
        let p = default_socket_path();
        assert_eq!(p, PathBuf::from("/tmp/linpodx-doctor-test/linpodx.sock"));
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn default_config_dir_uses_xdg_config() {
        let prev = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/linpodx-doctor-cfg-test");
        let p = default_config_dir();
        assert_eq!(p, PathBuf::from("/tmp/linpodx-doctor-cfg-test/linpodx"));
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn dir_presence_writable_passes() {
        // Create a temp dir, ensure check_dir_presence returns Pass and
        // cleans up its probe marker.
        let tmp = std::env::temp_dir().join(format!(
            "linpodx-doctor-dir-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let c = check_dir_presence("test-id", "test-label", &tmp, "anchor");
        assert_eq!(c.outcome, DoctorOutcome::Pass);
        // Probe marker should be cleaned up.
        assert!(!tmp.join(".linpodx-doctor-probe").exists());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn dir_presence_missing_is_warn() {
        let tmp = std::env::temp_dir().join(format!(
            "linpodx-doctor-missing-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        // Intentionally do NOT create it.
        let c = check_dir_presence("test-id", "test-label", &tmp, "anchor");
        assert_eq!(c.outcome, DoctorOutcome::Warn);
        assert!(c
            .fix_hint
            .as_deref()
            .unwrap_or("")
            .contains("docs/INSTALL.md#anchor"));
    }

    #[test]
    fn nix_geteuid_returns_some_uid() {
        // Should not panic and should return a plausible uid (0 or positive).
        let _uid = nix_geteuid();
    }
}
