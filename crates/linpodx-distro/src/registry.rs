//! Static registry of every shipped distro template.

use crate::templates::{alpine, arch, debian, fedora, nixos, ubuntu, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

/// Stateless lookup table over the six bundled templates.
pub struct Registry;

impl Registry {
    /// All templates in the canonical order from `DistroKind::ALL`.
    pub fn list() -> Vec<TemplateMeta> {
        DistroKind::ALL.into_iter().map(Self::inspect).collect()
    }

    pub fn inspect(kind: DistroKind) -> TemplateMeta {
        match kind {
            DistroKind::Ubuntu => ubuntu::template(),
            DistroKind::Fedora => fedora::template(),
            DistroKind::Arch => arch::template(),
            DistroKind::Debian => debian::template(),
            DistroKind::Alpine => alpine::template(),
            DistroKind::NixOS => nixos::template(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_returns_all_six_in_order() {
        let templates = Registry::list();
        assert_eq!(templates.len(), 6);
        let kinds: Vec<DistroKind> = templates.iter().map(|t| t.kind).collect();
        assert_eq!(kinds, DistroKind::ALL.to_vec());
    }

    #[test]
    fn inspect_returns_matching_kind() {
        for k in DistroKind::ALL {
            assert_eq!(Registry::inspect(k).kind, k);
        }
    }

    #[test]
    fn ubuntu_template_has_systemd_and_apt_packages() {
        let t = Registry::inspect(DistroKind::Ubuntu);
        assert_eq!(t.default_image, "docker.io/library/ubuntu:24.04");
        assert!(t.default_packages.contains(&"sudo".to_string()));
    }

    #[test]
    fn alpine_template_uses_ash_and_openrc() {
        let t = Registry::inspect(DistroKind::Alpine);
        assert_eq!(t.default_shell, "ash");
    }

    #[test]
    fn nixos_template_has_no_default_packages() {
        let t = Registry::inspect(DistroKind::NixOS);
        assert!(t.default_packages.is_empty());
    }
}
