use super::{desktop_passthrough, InitKind, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

pub fn template() -> TemplateMeta {
    TemplateMeta {
        kind: DistroKind::NixOS,
        display_name: "NixOS (nix base)".into(),
        default_image: "docker.io/nixos/nix:latest".into(),
        init_kind: InitKind::None,
        default_packages: Vec::new(),
        default_shell: "bash".into(),
        recommended_passthrough: desktop_passthrough(),
        post_create_hooks: Vec::new(),
        notes: "Nix base image; install packages via `nix-env -iA`.".into(),
    }
}
