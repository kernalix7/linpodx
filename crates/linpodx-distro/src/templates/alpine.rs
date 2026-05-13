use super::{desktop_passthrough, InitKind, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

pub fn template() -> TemplateMeta {
    TemplateMeta {
        kind: DistroKind::Alpine,
        display_name: "Alpine Linux".into(),
        default_image: "docker.io/library/alpine:latest".into(),
        init_kind: InitKind::OpenRC,
        default_packages: vec!["bash".into(), "git".into(), "vim".into(), "curl".into()],
        default_shell: "ash".into(),
        recommended_passthrough: desktop_passthrough(),
        post_create_hooks: Vec::new(),
        notes: "Alpine with OpenRC; tiny rootfs, ash by default.".into(),
    }
}
