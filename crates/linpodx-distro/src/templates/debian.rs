use super::{desktop_passthrough, InitKind, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

pub fn template() -> TemplateMeta {
    TemplateMeta {
        kind: DistroKind::Debian,
        display_name: "Debian Bookworm".into(),
        default_image: "docker.io/library/debian:bookworm".into(),
        init_kind: InitKind::Systemd,
        default_packages: vec!["sudo".into(), "vim".into(), "git".into(), "curl".into()],
        default_shell: "bash".into(),
        recommended_passthrough: desktop_passthrough(),
        post_create_hooks: Vec::new(),
        notes: "Debian stable with systemd. apt-based.".into(),
    }
}
