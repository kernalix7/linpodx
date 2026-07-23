//! Translate a [`PassthroughSpec`] into the corresponding `podman create` flags
//! (bind mounts, environment variables, device passes, group additions).
//!
//! All host-environment lookups go through the [`HostEnv`] trait so unit tests can
//! inject deterministic values instead of reading the developer's real `$HOME`.

use linpodx_common::passthrough::{AudioMode, PassthroughSpec};
use std::path::PathBuf;
use tokio::process::Command;
use tracing::{debug, warn};

/// Abstraction over the bits of host environment we read while building passthrough flags.
///
/// The default impl ([`SystemHostEnv`]) talks to `std::env`/`getuid`. Tests substitute
/// a `MockHostEnv` so behavior is deterministic.
pub trait HostEnv {
    fn var(&self, key: &str) -> Option<String>;
    fn uid(&self) -> u32;
    /// Resolve a host group name (e.g. `"render"`) to its numeric GID by reading the
    /// host's `/etc/group`. Returns `None` when the group does not exist on the host.
    ///
    /// GPU passthrough uses this instead of `--group-add <name>`: the *container's*
    /// `/etc/group` is what podman consults for name lookups, and minimal base images
    /// (Alpine, etc.) don't ship a `render` entry, so name-based `--group-add` fails
    /// deterministically at `podman start` even though the numeric GID is perfectly
    /// valid host-side. `--group-add <gid>` bypasses the container's group file
    /// entirely, so it works regardless of what the base image ships.
    fn group_gid(&self, name: &str) -> Option<u32>;
}

/// Real host-environment reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemHostEnv;

impl HostEnv for SystemHostEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
    fn uid(&self) -> u32 {
        // libc::getuid is unsafe; fall back to USER/UID env or a compile-time `nix` if added.
        // We don't want to add a syscall dep, so prefer $UID then default to 1000.
        std::env::var("UID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    }
    fn group_gid(&self, name: &str) -> Option<u32> {
        let contents = std::fs::read_to_string("/etc/group").ok()?;
        parse_group_gid(&contents, name)
    }
}

/// Parse a `/etc/group`-formatted string looking for `name`, returning its GID.
///
/// Format per line: `name:password:gid:members`. Malformed lines are skipped rather
/// than treated as errors — `/etc/group` on real hosts occasionally has stray blank
/// lines or comments injected by config-management tools.
fn parse_group_gid(contents: &str, name: &str) -> Option<u32> {
    contents.lines().find_map(|line| {
        let mut fields = line.splitn(4, ':');
        let entry_name = fields.next()?;
        if entry_name != name {
            return None;
        }
        let _password = fields.next()?;
        let gid = fields.next()?;
        gid.parse::<u32>().ok()
    })
}

/// Resolve `name` to a numeric GID via `env`, falling back to appending `--group-add
/// <gid>` on `cmd` when found. When the group doesn't exist on the host, emits a
/// `tracing::warn` and skips the flag entirely — silently dropping the grant is safer
/// than passing a name podman can't resolve inside a minimal container image.
fn add_group_by_name(cmd: &mut Command, env: &dyn HostEnv, name: &str) {
    match env.group_gid(name) {
        Some(gid) => {
            cmd.arg("--group-add").arg(gid.to_string());
        }
        None => {
            warn!(
                group = name,
                "gpu passthrough: host group not found; skipping --group-add"
            );
        }
    }
}

/// Env vars that are forwarded when [`PassthroughSpec::hidpi_inherit`] is set. The list is
/// intentionally narrow: GTK/Qt/GDK scaling + theme + cursor knobs only. New entries should
/// have a clear desktop-rendering reason — never bulk-forward `$PATH`-class vars.
const HIDPI_FORWARD: &[&str] = &[
    "GDK_SCALE",
    "GDK_DPI_SCALE",
    "GDK_BACKEND",
    "GTK_THEME",
    "GTK_OVERLAY_SCROLLING",
    "QT_SCALE_FACTOR",
    "QT_AUTO_SCREEN_SCALE_FACTOR",
    "QT_ENABLE_HIGHDPI_SCALING",
    "QT_QPA_PLATFORM",
    "QT_QPA_PLATFORMTHEME",
    "XCURSOR_SIZE",
    "XCURSOR_THEME",
];

/// Append the flags described by `spec` (using `env` for host lookups) to `cmd`.
pub fn apply_passthrough_with_env(cmd: &mut Command, spec: &PassthroughSpec, env: &dyn HostEnv) {
    if spec.is_empty() {
        return;
    }
    let xdg_runtime = env.var("XDG_RUNTIME_DIR");
    let uid = env.uid();
    // Container-side XDG_RUNTIME_DIR is always /run/user/<uid>; many GUI toolkits insist.
    let container_xdg = format!("/run/user/{uid}");

    if spec.wayland {
        if let Some(xdg) = xdg_runtime.as_deref() {
            let display = env
                .var("WAYLAND_DISPLAY")
                .unwrap_or_else(|| "wayland-0".to_string());
            let host_sock = PathBuf::from(xdg).join(&display);
            let target = format!("{container_xdg}/{display}");
            cmd.arg("--volume")
                .arg(format!("{}:{}", host_sock.display(), target));
            cmd.arg("--env").arg(format!("WAYLAND_DISPLAY={display}"));
            cmd.arg("--env")
                .arg(format!("XDG_RUNTIME_DIR={container_xdg}"));
        } else {
            warn!("wayland passthrough requested but XDG_RUNTIME_DIR unset; skipping wayland bind");
        }
    }

    if spec.x11 {
        cmd.arg("--volume").arg("/tmp/.X11-unix:/tmp/.X11-unix:ro");
        if let Some(d) = env.var("DISPLAY") {
            cmd.arg("--env").arg(format!("DISPLAY={d}"));
        } else {
            cmd.arg("--env").arg("DISPLAY=:0");
        }
        if let Some(xauth) = env.var("XAUTHORITY") {
            cmd.arg("--volume").arg(format!("{xauth}:{xauth}:ro"));
            cmd.arg("--env").arg(format!("XAUTHORITY={xauth}"));
        }
    }

    match spec.audio {
        AudioMode::None => {}
        AudioMode::PipeWire => {
            if let Some(xdg) = xdg_runtime.as_deref() {
                let host_sock = PathBuf::from(xdg).join("pipewire-0");
                let target = format!("{container_xdg}/pipewire-0");
                cmd.arg("--volume")
                    .arg(format!("{}:{}", host_sock.display(), target));
                cmd.arg("--env")
                    .arg(format!("PIPEWIRE_RUNTIME_DIR={container_xdg}"));
                // Many apps look at XDG_RUNTIME_DIR rather than PIPEWIRE_RUNTIME_DIR.
                cmd.arg("--env")
                    .arg(format!("XDG_RUNTIME_DIR={container_xdg}"));
            } else {
                warn!("pipewire passthrough requested but XDG_RUNTIME_DIR unset");
            }
        }
        AudioMode::Pulse => {
            if let Some(xdg) = xdg_runtime.as_deref() {
                let host_dir = PathBuf::from(xdg).join("pulse");
                let target = format!("{container_xdg}/pulse");
                cmd.arg("--volume")
                    .arg(format!("{}:{}", host_dir.display(), target));
                cmd.arg("--env")
                    .arg(format!("PULSE_SERVER=unix:{container_xdg}/pulse/native"));
                cmd.arg("--env")
                    .arg(format!("XDG_RUNTIME_DIR={container_xdg}"));
            } else {
                warn!("pulse passthrough requested but XDG_RUNTIME_DIR unset");
            }
        }
    }

    if spec.gpu {
        cmd.arg("--device").arg("/dev/dri");
        add_group_by_name(cmd, env, "video");
        add_group_by_name(cmd, env, "render");
    }

    if spec.dbus_session {
        // Per-user DBus socket. Container-side path mirrors host so libdbus auto-picks it.
        let host_bus = format!("/run/user/{uid}/bus");
        let target = format!("{container_xdg}/bus");
        cmd.arg("--volume").arg(format!("{host_bus}:{target}"));
        cmd.arg("--env")
            .arg(format!("DBUS_SESSION_BUS_ADDRESS=unix:path={target}"));
    }

    if spec.clipboard {
        // No bind required; the toolkits ride on the wayland/x11 socket. We mark intent via
        // a label so downstream tooling can confirm clipboard helpers are installed.
        cmd.arg("--label").arg("linpodx.clipboard=requested");
    }

    if spec.hidpi_inherit {
        for key in HIDPI_FORWARD {
            if let Some(v) = env.var(key) {
                cmd.arg("--env").arg(format!("{key}={v}"));
            }
        }
    }

    if let Some(slug) = &spec.register_app_menu {
        // The actual .desktop file is generated by the GUI/CLI layer; the runtime just
        // tags the container so we know which desktop entry it is associated with.
        cmd.arg("--label").arg(format!("linpodx.app_menu={slug}"));
    }

    debug!(?spec, "passthrough flags applied");
}

/// Convenience wrapper around [`apply_passthrough_with_env`] using [`SystemHostEnv`].
pub fn apply_passthrough(cmd: &mut Command, spec: &PassthroughSpec) {
    apply_passthrough_with_env(cmd, spec, &SystemHostEnv);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsStr;

    #[derive(Default)]
    struct MockHostEnv {
        vars: HashMap<String, String>,
        uid: u32,
        groups: HashMap<String, u32>,
    }

    impl MockHostEnv {
        fn new(uid: u32) -> Self {
            Self {
                uid,
                vars: HashMap::new(),
                groups: HashMap::new(),
            }
        }
        fn set(mut self, k: &str, v: &str) -> Self {
            self.vars.insert(k.into(), v.into());
            self
        }
        fn set_group(mut self, name: &str, gid: u32) -> Self {
            self.groups.insert(name.into(), gid);
            self
        }
    }

    impl HostEnv for MockHostEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
        fn uid(&self) -> u32 {
            self.uid
        }
        fn group_gid(&self, name: &str) -> Option<u32> {
            self.groups.get(name).copied()
        }
    }

    fn args_of(cmd: &Command) -> Vec<String> {
        cmd.as_std()
            .get_args()
            .map(|s: &OsStr| s.to_string_lossy().into_owned())
            .collect()
    }

    fn contains_pair(args: &[String], flag: &str, value_substr: &str) -> bool {
        for win in args.windows(2) {
            if win[0] == flag && win[1].contains(value_substr) {
                return true;
            }
        }
        false
    }

    #[test]
    fn empty_spec_emits_no_flags() {
        let env = MockHostEnv::new(1000);
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &PassthroughSpec::default(), &env);
        assert!(args_of(&cmd).is_empty());
    }

    #[test]
    fn wayland_uses_wayland_display_var() {
        let env = MockHostEnv::new(1000)
            .set("XDG_RUNTIME_DIR", "/run/user/1000")
            .set("WAYLAND_DISPLAY", "wayland-1");
        let spec = PassthroughSpec {
            wayland: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--volume",
            "/run/user/1000/wayland-1:/run/user/1000/wayland-1"
        ));
        assert!(contains_pair(&args, "--env", "WAYLAND_DISPLAY=wayland-1"));
        assert!(contains_pair(
            &args,
            "--env",
            "XDG_RUNTIME_DIR=/run/user/1000"
        ));
    }

    #[test]
    fn wayland_defaults_display_to_zero() {
        let env = MockHostEnv::new(1000).set("XDG_RUNTIME_DIR", "/run/user/1000");
        let spec = PassthroughSpec {
            wayland: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--volume",
            "/run/user/1000/wayland-0:/run/user/1000/wayland-0"
        ));
        assert!(contains_pair(&args, "--env", "WAYLAND_DISPLAY=wayland-0"));
    }

    #[test]
    fn wayland_skipped_without_xdg_runtime_dir() {
        let env = MockHostEnv::new(1000);
        let spec = PassthroughSpec {
            wayland: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        assert!(args_of(&cmd).is_empty());
    }

    #[test]
    fn x11_binds_socket_and_forwards_display() {
        let env = MockHostEnv::new(1000)
            .set("DISPLAY", ":1")
            .set("XAUTHORITY", "/home/u/.Xauthority");
        let spec = PassthroughSpec {
            x11: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--volume",
            "/tmp/.X11-unix:/tmp/.X11-unix:ro"
        ));
        assert!(contains_pair(&args, "--env", "DISPLAY=:1"));
        assert!(contains_pair(
            &args,
            "--volume",
            "/home/u/.Xauthority:/home/u/.Xauthority:ro"
        ));
        assert!(contains_pair(
            &args,
            "--env",
            "XAUTHORITY=/home/u/.Xauthority"
        ));
    }

    #[test]
    fn x11_defaults_display_when_unset() {
        let env = MockHostEnv::new(1000);
        let spec = PassthroughSpec {
            x11: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(&args, "--env", "DISPLAY=:0"));
    }

    #[test]
    fn pipewire_audio_binds_socket() {
        let env = MockHostEnv::new(1000).set("XDG_RUNTIME_DIR", "/run/user/1000");
        let spec = PassthroughSpec {
            audio: AudioMode::PipeWire,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--volume",
            "/run/user/1000/pipewire-0:/run/user/1000/pipewire-0"
        ));
        assert!(contains_pair(
            &args,
            "--env",
            "PIPEWIRE_RUNTIME_DIR=/run/user/1000"
        ));
    }

    #[test]
    fn pulse_audio_binds_directory_and_sets_server() {
        let env = MockHostEnv::new(1000).set("XDG_RUNTIME_DIR", "/run/user/1000");
        let spec = PassthroughSpec {
            audio: AudioMode::Pulse,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--volume",
            "/run/user/1000/pulse:/run/user/1000/pulse"
        ));
        assert!(contains_pair(
            &args,
            "--env",
            "PULSE_SERVER=unix:/run/user/1000/pulse/native"
        ));
    }

    #[test]
    fn gpu_passes_dri_and_resolves_groups_to_numeric_gid() {
        let env = MockHostEnv::new(1000)
            .set_group("video", 44)
            .set_group("render", 993);
        let spec = PassthroughSpec {
            gpu: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(&args, "--device", "/dev/dri"));
        // Numeric GIDs only — never the bare name — so the flag works regardless of
        // whether the *container's* /etc/group has a matching entry.
        assert!(contains_pair(&args, "--group-add", "44"));
        assert!(contains_pair(&args, "--group-add", "993"));
        assert!(!args.iter().any(|a| a == "video"));
        assert!(!args.iter().any(|a| a == "render"));
    }

    #[test]
    fn gpu_skips_group_add_when_host_group_missing() {
        // Neither "video" nor "render" resolves on this mock host (e.g. a headless CI
        // runner with no GPU groups). The device is still passed through; the missing
        // groups are dropped rather than causing a podman-start failure downstream.
        let env = MockHostEnv::new(1000);
        let spec = PassthroughSpec {
            gpu: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(&args, "--device", "/dev/dri"));
        assert!(!args.iter().any(|a| a == "--group-add"));
    }

    #[test]
    fn gpu_resolves_only_the_groups_present_on_host() {
        // "video" exists, "render" doesn't (plausible on an older host kernel without
        // a DRM render node) — video should still resolve numerically.
        let env = MockHostEnv::new(1000).set_group("video", 44);
        let spec = PassthroughSpec {
            gpu: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(&args, "--group-add", "44"));
        let group_add_count = args.iter().filter(|a| a.as_str() == "--group-add").count();
        assert_eq!(
            group_add_count, 1,
            "only the resolvable group should be added"
        );
    }

    #[test]
    fn parse_group_gid_finds_matching_entry() {
        let etc_group = "root:x:0:\nvideo:x:44:user1,user2\nrender:x:993:user1\n";
        assert_eq!(parse_group_gid(etc_group, "video"), Some(44));
        assert_eq!(parse_group_gid(etc_group, "render"), Some(993));
    }

    #[test]
    fn parse_group_gid_returns_none_for_missing_group() {
        let etc_group = "root:x:0:\nvideo:x:44:user1\n";
        assert_eq!(parse_group_gid(etc_group, "render"), None);
    }

    #[test]
    fn parse_group_gid_skips_malformed_lines() {
        // A blank line and a line missing the gid field should not panic and should
        // not be mistaken for the target group.
        let etc_group = "\nrender::\nrender:x:993:\n";
        assert_eq!(parse_group_gid(etc_group, "render"), Some(993));
    }

    #[test]
    fn parse_group_gid_handles_non_numeric_gid_gracefully() {
        let etc_group = "render:x:notanumber:\n";
        assert_eq!(parse_group_gid(etc_group, "render"), None);
    }

    #[test]
    fn dbus_session_binds_user_bus() {
        let env = MockHostEnv::new(1234);
        let spec = PassthroughSpec {
            dbus_session: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--volume",
            "/run/user/1234/bus:/run/user/1234/bus"
        ));
        assert!(contains_pair(
            &args,
            "--env",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1234/bus"
        ));
    }

    #[test]
    fn hidpi_inherit_only_forwards_known_keys() {
        let env = MockHostEnv::new(1000)
            .set("GDK_SCALE", "2")
            .set("QT_SCALE_FACTOR", "1.5")
            .set("PATH", "/usr/bin")
            .set("HOME", "/home/u");
        let spec = PassthroughSpec {
            hidpi_inherit: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(&args, "--env", "GDK_SCALE=2"));
        assert!(contains_pair(&args, "--env", "QT_SCALE_FACTOR=1.5"));
        // Non-HiDPI vars must NOT leak through.
        assert!(!args.iter().any(|a| a.starts_with("PATH=")));
        assert!(!args.iter().any(|a| a.starts_with("HOME=")));
    }

    #[test]
    fn register_app_menu_emits_label() {
        let env = MockHostEnv::new(1000);
        let spec = PassthroughSpec {
            register_app_menu: Some("alpine-shell".into()),
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--label",
            "linpodx.app_menu=alpine-shell"
        ));
    }

    #[test]
    fn clipboard_emits_intent_label() {
        let env = MockHostEnv::new(1000);
        let spec = PassthroughSpec {
            clipboard: true,
            ..Default::default()
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(contains_pair(
            &args,
            "--label",
            "linpodx.clipboard=requested"
        ));
    }

    #[test]
    fn full_spec_emits_all_categories() {
        let env = MockHostEnv::new(1000)
            .set("XDG_RUNTIME_DIR", "/run/user/1000")
            .set("WAYLAND_DISPLAY", "wayland-0")
            .set("DISPLAY", ":0")
            .set("GDK_SCALE", "2");
        let spec = PassthroughSpec {
            wayland: true,
            x11: true,
            audio: AudioMode::PipeWire,
            gpu: true,
            dbus_session: true,
            clipboard: true,
            hidpi_inherit: true,
            register_app_menu: Some("demo".into()),
        };
        let mut cmd = Command::new("podman");
        apply_passthrough_with_env(&mut cmd, &spec, &env);
        let args = args_of(&cmd);
        assert!(args.iter().any(|a| a.contains("wayland-0")));
        assert!(args.iter().any(|a| a.contains("/tmp/.X11-unix")));
        assert!(args.iter().any(|a| a.contains("pipewire-0")));
        assert!(args.iter().any(|a| a == "/dev/dri"));
        assert!(args.iter().any(|a| a.contains("/bus:")));
        assert!(args.iter().any(|a| a.contains("GDK_SCALE=2")));
        assert!(args
            .iter()
            .any(|a| a.contains("linpodx.clipboard=requested")));
        assert!(args.iter().any(|a| a.contains("linpodx.app_menu=demo")));
    }
}
