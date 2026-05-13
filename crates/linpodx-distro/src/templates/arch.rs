use super::{desktop_passthrough, InitKind, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

pub fn template() -> TemplateMeta {
    TemplateMeta {
        kind: DistroKind::Arch,
        display_name: "Arch Linux".into(),
        default_image: "docker.io/library/archlinux:latest".into(),
        init_kind: InitKind::Systemd,
        default_packages: vec!["base-devel".into(), "git".into(), "vim".into()],
        default_shell: "bash".into(),
        recommended_passthrough: desktop_passthrough(),
        post_create_hooks: Vec::new(),
        notes: "Arch rolling release with systemd. pacman-based.".into(),
    }
}
