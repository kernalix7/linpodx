use super::{desktop_passthrough, InitKind, TemplateMeta};
use linpodx_common::passthrough::DistroKind;

pub fn template() -> TemplateMeta {
    TemplateMeta {
        kind: DistroKind::Ubuntu,
        display_name: "Ubuntu 24.04 LTS".into(),
        default_image: "docker.io/library/ubuntu:24.04".into(),
        init_kind: InitKind::Systemd,
        default_packages: vec![
            "sudo".into(),
            "vim".into(),
            "git".into(),
            "curl".into(),
            "ca-certificates".into(),
        ],
        default_shell: "bash".into(),
        recommended_passthrough: desktop_passthrough(),
        post_create_hooks: Vec::new(),
        notes: "Ubuntu LTS with systemd. Pair with vm_mode for a long-lived dev box.".into(),
    }
}
