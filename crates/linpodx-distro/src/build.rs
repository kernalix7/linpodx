//! Custom-image build pipeline.
//!
//! Generates a small Dockerfile per distro kind that layers the user-supplied package
//! list on top of the template's default image, then drives `podman build` from a
//! disposable tempdir. The resulting image is tagged
//! `linpodx-distro/<kind>:<base_tag>-custom-<hash8>` so identical inputs yield identical
//! tags and the user can recognize their custom builds.

use crate::registry::Registry;
use crate::templates::TemplateMeta;
use crate::{DistroError, Result};
use linpodx_common::passthrough::DistroKind;
use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::{info, instrument};

/// Inputs for one custom-image build.
#[derive(Debug, Clone)]
pub struct BuildSpec {
    pub kind: DistroKind,
    /// Override the template's base image tag (e.g. `"22.04"` for ubuntu). When set, only
    /// the trailing tag of `default_image` is replaced.
    pub base_tag: Option<String>,
    /// Extra packages installed on top of the template defaults. Order is preserved for
    /// the user-visible Dockerfile but sorted+deduped for tag-hash stability.
    pub include: Vec<String>,
}

impl BuildSpec {
    /// Generate the Dockerfile string for inspection or testing.
    pub fn dockerfile(&self) -> String {
        let template = Registry::inspect(self.kind);
        let base_image = self.resolved_base_image(&template);
        let merged = self.merged_packages(&template);
        let install_line = match self.kind {
            DistroKind::Ubuntu | DistroKind::Debian => apt_install_line(&merged),
            DistroKind::Fedora => dnf_install_line(&merged),
            DistroKind::Arch => pacman_install_line(&merged),
            DistroKind::Alpine => apk_install_line(&merged),
            DistroKind::NixOS => nix_install_line(&merged),
        };
        let label = format!(
            "LABEL io.linpodx.distro=\"{}\" io.linpodx.template=\"linpodx-distro\"",
            self.kind.as_str()
        );
        if install_line.is_empty() {
            format!("FROM {base_image}\n{label}\n")
        } else {
            format!("FROM {base_image}\n{label}\n{install_line}\n")
        }
    }

    /// `linpodx-distro/<kind>:<base_tag>-custom-<hash8>` — deterministic for identical
    /// `(kind, base_tag, sorted-deduped include)` tuples.
    pub fn image_tag(&self) -> String {
        let template = Registry::inspect(self.kind);
        let base_tag = self.effective_base_tag(&template);
        let hash = self.tag_hash();
        format!(
            "linpodx-distro/{}:{}-custom-{}",
            self.kind.as_str(),
            base_tag,
            hash
        )
    }

    /// Drive `podman build` and return `(image_ref, duration_ms)`.
    ///
    /// `podman_bin` is the path to the podman binary; it lets the caller (the daemon)
    /// honour `PodmanConfig::binary` overrides. `podman_root` / `podman_runroot` get
    /// forwarded as `--root` / `--runroot` if present, mirroring the runtime adapter so
    /// integration tests that target a disposable Podman state work end to end.
    #[instrument(skip(self), fields(kind = %self.kind))]
    pub async fn build(
        &self,
        podman_bin: &str,
        podman_root: Option<&std::path::Path>,
        podman_runroot: Option<&std::path::Path>,
    ) -> Result<(String, u64)> {
        let dockerfile = self.dockerfile();
        let tag = self.image_tag();

        let ctx = tempfile::tempdir().map_err(DistroError::Io)?;
        let dockerfile_path = ctx.path().join("Dockerfile");
        tokio::fs::write(&dockerfile_path, &dockerfile)
            .await
            .map_err(DistroError::Io)?;

        let mut cmd = tokio::process::Command::new(podman_bin);
        if let Some(root) = podman_root {
            cmd.arg("--root").arg(root);
        }
        if let Some(runroot) = podman_runroot {
            cmd.arg("--runroot").arg(runroot);
        }
        cmd.arg("build")
            .arg("-f")
            .arg(&dockerfile_path)
            .arg("-t")
            .arg(&tag)
            .arg(ctx.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let started = Instant::now();
        let output = cmd.output().await.map_err(DistroError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(DistroError::Runtime(format!(
                "podman build failed: {stderr}"
            )));
        }
        let elapsed = started.elapsed();
        info!(image = %tag, ms = elapsed.as_millis() as u64, "podman build complete");
        Ok((tag, elapsed.as_millis() as u64))
    }

    fn resolved_base_image(&self, template: &TemplateMeta) -> String {
        match &self.base_tag {
            Some(tag) => replace_image_tag(&template.default_image, tag),
            None => template.default_image.clone(),
        }
    }

    fn effective_base_tag(&self, template: &TemplateMeta) -> String {
        if let Some(t) = &self.base_tag {
            return t.clone();
        }
        // Pull the trailing `:tag` from the default image, fall back to "latest".
        template
            .default_image
            .rsplit_once(':')
            .map(|(_, t)| t.to_string())
            .unwrap_or_else(|| "latest".to_string())
    }

    fn merged_packages(&self, template: &TemplateMeta) -> Vec<String> {
        let mut out = template.default_packages.clone();
        for p in &self.include {
            if !out.iter().any(|x| x == p) {
                out.push(p.clone());
            }
        }
        out
    }

    fn tag_hash(&self) -> String {
        let mut sorted = self.merged_packages(&Registry::inspect(self.kind));
        sorted.sort();
        sorted.dedup();
        let payload = format!("{}|{:?}|{:?}", self.kind.as_str(), self.base_tag, sorted);
        let mut h = Sha256::new();
        h.update(payload.as_bytes());
        let hex = hex_encode(&h.finalize());
        hex.chars().take(8).collect()
    }
}

fn replace_image_tag(image: &str, new_tag: &str) -> String {
    match image.rsplit_once(':') {
        Some((repo, _)) => format!("{repo}:{new_tag}"),
        None => format!("{image}:{new_tag}"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn apt_install_line(pkgs: &[String]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    format!(
        "RUN apt-get update && apt-get install -y --no-install-recommends {} && rm -rf /var/lib/apt/lists/*",
        pkgs.join(" ")
    )
}

fn dnf_install_line(pkgs: &[String]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    format!("RUN dnf install -y {} && dnf clean all", pkgs.join(" "))
}

fn pacman_install_line(pkgs: &[String]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    format!("RUN pacman -Syu --noconfirm {}", pkgs.join(" "))
}

fn apk_install_line(pkgs: &[String]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    format!("RUN apk add --no-cache {}", pkgs.join(" "))
}

fn nix_install_line(pkgs: &[String]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    let attrs: Vec<String> = pkgs.iter().map(|p| format!("nixpkgs.{p}")).collect();
    format!("RUN nix-env -iA {}", attrs.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_dockerfile_contains_apt_install() {
        let spec = BuildSpec {
            kind: DistroKind::Ubuntu,
            base_tag: None,
            include: vec!["jq".into()],
        };
        let df = spec.dockerfile();
        assert!(df.starts_with("FROM docker.io/library/ubuntu:24.04\n"));
        assert!(df.contains("apt-get install -y"));
        assert!(df.contains("jq"));
        assert!(df.contains("sudo")); // template default
    }

    #[test]
    fn fedora_dockerfile_uses_dnf() {
        let spec = BuildSpec {
            kind: DistroKind::Fedora,
            base_tag: Some("39".into()),
            include: Vec::new(),
        };
        let df = spec.dockerfile();
        assert!(df.starts_with("FROM docker.io/library/fedora:39\n"));
        assert!(df.contains("dnf install -y"));
    }

    #[test]
    fn arch_dockerfile_uses_pacman() {
        let spec = BuildSpec {
            kind: DistroKind::Arch,
            base_tag: None,
            include: vec!["fish".into()],
        };
        let df = spec.dockerfile();
        assert!(df.contains("pacman -Syu --noconfirm"));
        assert!(df.contains("fish"));
    }

    #[test]
    fn alpine_dockerfile_uses_apk() {
        let spec = BuildSpec {
            kind: DistroKind::Alpine,
            base_tag: None,
            include: Vec::new(),
        };
        let df = spec.dockerfile();
        assert!(df.contains("apk add --no-cache"));
    }

    #[test]
    fn nixos_dockerfile_with_no_packages_has_no_run_line() {
        let spec = BuildSpec {
            kind: DistroKind::NixOS,
            base_tag: None,
            include: Vec::new(),
        };
        let df = spec.dockerfile();
        assert!(!df.contains("RUN"));
    }

    #[test]
    fn nixos_dockerfile_with_packages_uses_nix_env() {
        let spec = BuildSpec {
            kind: DistroKind::NixOS,
            base_tag: None,
            include: vec!["hello".into()],
        };
        let df = spec.dockerfile();
        assert!(df.contains("nix-env -iA nixpkgs.hello"));
    }

    #[test]
    fn debian_dockerfile_uses_apt() {
        let spec = BuildSpec {
            kind: DistroKind::Debian,
            base_tag: None,
            include: Vec::new(),
        };
        let df = spec.dockerfile();
        assert!(df.contains("apt-get install -y"));
    }

    #[test]
    fn image_tag_is_deterministic() {
        let a = BuildSpec {
            kind: DistroKind::Alpine,
            base_tag: None,
            include: vec!["b".into(), "a".into()],
        };
        let b = BuildSpec {
            kind: DistroKind::Alpine,
            base_tag: None,
            include: vec!["a".into(), "b".into()],
        };
        // Order of `include` shouldn't change the tag (sort+dedup).
        assert_eq!(a.image_tag(), b.image_tag());
        assert!(a
            .image_tag()
            .starts_with("linpodx-distro/alpine:latest-custom-"));
    }

    #[test]
    fn image_tag_changes_on_different_packages() {
        let a = BuildSpec {
            kind: DistroKind::Alpine,
            base_tag: None,
            include: vec!["a".into()],
        };
        let b = BuildSpec {
            kind: DistroKind::Alpine,
            base_tag: None,
            include: vec!["b".into()],
        };
        assert_ne!(a.image_tag(), b.image_tag());
    }

    #[test]
    fn replace_image_tag_swaps_only_tag() {
        assert_eq!(
            replace_image_tag("docker.io/library/ubuntu:24.04", "22.04"),
            "docker.io/library/ubuntu:22.04"
        );
        assert_eq!(replace_image_tag("nginx", "1.27"), "nginx:1.27");
    }

    #[test]
    fn dockerfile_includes_label() {
        let spec = BuildSpec {
            kind: DistroKind::Ubuntu,
            base_tag: None,
            include: Vec::new(),
        };
        assert!(spec.dockerfile().contains("io.linpodx.distro=\"ubuntu\""));
    }
}
