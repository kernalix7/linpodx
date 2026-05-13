//! GUI / desktop passthrough specification + multi-distro descriptor types.
//!
//! These live in `linpodx-common` so every crate (runtime, sandbox, distro, gui, cli, mcp)
//! can speak the same vocabulary without depending on each other.

use serde::{Deserialize, Serialize};

/// Per-container desktop / device passthrough grants.
///
/// All fields default to `false` / `None` so the strictest profile is the empty struct.
/// The runtime layer translates each granted field into bind mounts, env vars, and
/// `--device` flags when invoking `podman create`. The sandbox layer audits the grant
/// at container-create time so the user can later reconstruct what a given container saw
/// from the host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassthroughSpec {
    /// Bind-mount the host Wayland socket into the container.
    #[serde(default)]
    pub wayland: bool,
    /// Bind-mount `/tmp/.X11-unix` and forward `DISPLAY`/`XAUTHORITY`.
    #[serde(default)]
    pub x11: bool,
    /// Audio passthrough mode (PipeWire socket, PulseAudio socket, or off).
    #[serde(default)]
    pub audio: AudioMode,
    /// Pass `/dev/dri` for hardware-accelerated GL / VA-API.
    #[serde(default)]
    pub gpu: bool,
    /// Forward the user's DBus session bus.
    #[serde(default)]
    pub dbus_session: bool,
    /// Provide a clipboard helper (wl-clipboard or xclip) inside the container.
    #[serde(default)]
    pub clipboard: bool,
    /// Inherit HiDPI / font / theme env vars (GTK_*, QT_*, GDK_DPI_SCALE, …).
    #[serde(default)]
    pub hidpi_inherit: bool,
    /// If set, generate `~/.local/share/applications/linpodx-<value>.desktop`
    /// so the GUI app appears in the host application menu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_app_menu: Option<String>,
}

impl PassthroughSpec {
    /// Returns true if any passthrough is requested. Used to short-circuit the runtime
    /// layer when the spec is fully empty.
    pub fn is_empty(&self) -> bool {
        !self.wayland
            && !self.x11
            && matches!(self.audio, AudioMode::None)
            && !self.gpu
            && !self.dbus_session
            && !self.clipboard
            && !self.hidpi_inherit
            && self.register_app_menu.is_none()
    }
}

/// Audio passthrough mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioMode {
    #[default]
    None,
    /// Bind `$XDG_RUNTIME_DIR/pipewire-0`. Modern default.
    PipeWire,
    /// Bind PulseAudio socket. Legacy fallback.
    Pulse,
}

/// Distro template kinds shipped by `linpodx-distro`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistroKind {
    Ubuntu,
    Fedora,
    Arch,
    Debian,
    Alpine,
    #[serde(rename = "nixos")]
    NixOS,
}

impl DistroKind {
    pub const ALL: [DistroKind; 6] = [
        Self::Ubuntu,
        Self::Fedora,
        Self::Arch,
        Self::Debian,
        Self::Alpine,
        Self::NixOS,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ubuntu => "ubuntu",
            Self::Fedora => "fedora",
            Self::Arch => "arch",
            Self::Debian => "debian",
            Self::Alpine => "alpine",
            Self::NixOS => "nixos",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ubuntu" => Ok(Self::Ubuntu),
            "fedora" | "rhel" | "centos" => Ok(Self::Fedora),
            "arch" | "archlinux" => Ok(Self::Arch),
            "debian" => Ok(Self::Debian),
            "alpine" => Ok(Self::Alpine),
            "nixos" | "nix" => Ok(Self::NixOS),
            other => Err(format!(
                "unknown distro '{other}' (expected: ubuntu, fedora, arch, debian, alpine, nixos)"
            )),
        }
    }
}

impl std::fmt::Display for DistroKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Phase 7: pluggable snapshot backend selector.
///
/// `PodmanCommit` is the default and most-portable backend (uses `podman commit` to
/// build a new image). `Overlayfs` stacks read-only lowerdirs and a writable upperdir
/// — needs the host kernel + filesystem support and is faster for repeated snapshots.
/// `Btrfs` uses subvolume snapshots — fastest where the storage is already btrfs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotBackendKind {
    #[default]
    PodmanCommit,
    Overlayfs,
    Btrfs,
}

impl SnapshotBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PodmanCommit => "podman_commit",
            Self::Overlayfs => "overlayfs",
            Self::Btrfs => "btrfs",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "podman_commit" | "podman-commit" | "commit" | "podman" => Ok(Self::PodmanCommit),
            "overlayfs" | "overlay" => Ok(Self::Overlayfs),
            "btrfs" => Ok(Self::Btrfs),
            other => Err(format!(
                "unknown snapshot backend '{other}' (expected: podman_commit, overlayfs, btrfs)"
            )),
        }
    }
}

impl std::fmt::Display for SnapshotBackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_is_empty_when_default() {
        assert!(PassthroughSpec::default().is_empty());
    }

    #[test]
    fn passthrough_not_empty_when_wayland_set() {
        let spec = PassthroughSpec {
            wayland: true,
            ..Default::default()
        };
        assert!(!spec.is_empty());
    }

    #[test]
    fn passthrough_json_round_trip() {
        let spec = PassthroughSpec {
            wayland: true,
            audio: AudioMode::PipeWire,
            gpu: true,
            register_app_menu: Some("alpine-shell".into()),
            ..Default::default()
        };
        let s = serde_json::to_string(&spec).unwrap();
        let back: PassthroughSpec = serde_json::from_str(&s).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn audio_mode_serializes_snake_case() {
        let s = serde_json::to_string(&AudioMode::PipeWire).unwrap();
        assert_eq!(s, "\"pipe_wire\"");
        let parsed: AudioMode = serde_json::from_str("\"pulse\"").unwrap();
        assert_eq!(parsed, AudioMode::Pulse);
    }

    #[test]
    fn distro_kind_round_trip() {
        for k in DistroKind::ALL {
            let s = k.as_str();
            assert_eq!(DistroKind::parse(s).unwrap(), k);
        }
        assert_eq!(DistroKind::parse("UBUNTU").unwrap(), DistroKind::Ubuntu);
        assert_eq!(DistroKind::parse("nix").unwrap(), DistroKind::NixOS);
        assert!(DistroKind::parse("plan9").is_err());
    }

    #[test]
    fn distro_kind_serializes_snake_case() {
        let s = serde_json::to_string(&DistroKind::NixOS).unwrap();
        assert_eq!(s, "\"nixos\"");
        let parsed: DistroKind = serde_json::from_str("\"alpine\"").unwrap();
        assert_eq!(parsed, DistroKind::Alpine);
    }
}
