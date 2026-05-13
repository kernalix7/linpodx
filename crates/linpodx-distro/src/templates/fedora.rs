use super::{desktop_passthrough, InitKind, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

pub fn template() -> TemplateMeta {
    TemplateMeta {
        kind: DistroKind::Fedora,
        display_name: "Fedora (latest)".into(),
        default_image: "docker.io/library/fedora:latest".into(),
        init_kind: InitKind::Systemd,
        default_packages: vec![
            "sudo".into(),
            "vim-enhanced".into(),
            "git".into(),
            "curl".into(),
        ],
        default_shell: "bash".into(),
        recommended_passthrough: desktop_passthrough(),
        post_create_hooks: Vec::new(),
        notes: "Fedora rolling tag with systemd. dnf-based.".into(),
    }
}
