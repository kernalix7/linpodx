//! Static distro template descriptors.
//!
//! Each submodule exposes a single `pub fn template() -> TemplateMeta`. The set is
//! enumerated by [`crate::registry::Registry`].

use linpodx_common::passthrough::{AudioMode, DistroKind, PassthroughSpec};
use serde::{Deserialize, Serialize};

pub mod alpine;
pub mod arch;
pub mod debian;
pub mod fedora;
pub mod nixos;
pub mod ubuntu;

/// PID-1 / init style baked into the template image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitKind {
    /// No init system; container runs the shell directly.
    None,
    /// systemd-in-container (`--systemd=true`).
    Systemd,
    /// Alpine-style OpenRC.
    OpenRC,
}

impl InitKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Systemd => "systemd",
            Self::OpenRC => "openrc",
        }
    }
}

/// Static template metadata.
///
/// Exposes the defaults the daemon uses when a user runs `linpodx distro create
/// --kind=<kind>` without overrides. `recommended_passthrough` is the suggested set of
/// host integrations for a desktop distro experience; the user can layer additional
/// grants via `DistroCreateParams::passthrough`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub kind: DistroKind,
    pub display_name: String,
    pub default_image: String,
    pub init_kind: InitKind,
    /// Explicit per-template override for the container's entry command, used when
    /// `default_image` does not actually run an init system as PID 1.
    ///
    /// `init_kind` describes what a *fully provisioned* instance of this distro would
    /// use as PID 1, but every `default_image` today is a stock upstream base image —
    /// none of them ship with systemd/OpenRC configured to run as the container's
    /// entrypoint. Left to the image's own default `CMD` (typically an interactive
    /// shell), the container exits the instant it starts under `--detach` (no TTY, no
    /// stdin, EOF immediately). `Some(cmd)` keeps the container alive so `distro enter`
    /// / `exec` has something to attach to; `None` means the image genuinely boots a
    /// real init as PID 1 and no override is needed (no template sets this today, but
    /// a future custom-built systemd image could).
    pub keep_alive_command: Option<Vec<String>>,
    pub default_packages: Vec<String>,
    pub default_shell: String,
    pub recommended_passthrough: PassthroughSpec,
    pub post_create_hooks: Vec<String>,
    pub notes: String,
}

/// Standard keep-alive command for templates whose `default_image` does not run a
/// real init system as PID 1. `sleep infinity` is available via coreutils/busybox on
/// every template image in this registry.
pub(crate) fn standard_keep_alive() -> Option<Vec<String>> {
    Some(vec!["sleep".to_string(), "infinity".to_string()])
}

/// Default desktop-friendly passthrough set: Wayland + PipeWire + GPU + clipboard +
/// HiDPI inheritance. DBus and X11 are intentionally omitted (opt-in per workload).
pub(crate) fn desktop_passthrough() -> PassthroughSpec {
    PassthroughSpec {
        wayland: true,
        x11: false,
        audio: AudioMode::PipeWire,
        gpu: true,
        dbus_session: false,
        clipboard: true,
        hidpi_inherit: true,
        register_app_menu: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_kind_strings_are_stable() {
        assert_eq!(InitKind::None.as_str(), "none");
        assert_eq!(InitKind::Systemd.as_str(), "systemd");
        assert_eq!(InitKind::OpenRC.as_str(), "openrc");
    }

    #[test]
    fn desktop_passthrough_is_not_empty() {
        assert!(!desktop_passthrough().is_empty());
    }
}
