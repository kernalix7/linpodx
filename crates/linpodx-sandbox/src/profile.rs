use crate::schema::{SandboxProfile, PROFILE_SCHEMA_VERSION};
use linpodx_common::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Default profiles directory: `${XDG_CONFIG_HOME:-~/.config}/linpodx/profiles`.
pub fn default_profiles_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("linpodx").join("profiles");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/linpodx/profiles");
    }
    PathBuf::from("./linpodx-profiles")
}

/// Load a single profile from a YAML file. Verifies `version == PROFILE_SCHEMA_VERSION`.
pub async fn load_profile(path: &Path) -> Result<SandboxProfile> {
    let content = tokio::fs::read_to_string(path).await?;
    parse_profile(&content, path)
}

/// Synchronous parse helper used by the loader and tests.
pub fn parse_profile(content: &str, source: &Path) -> Result<SandboxProfile> {
    let profile: SandboxProfile = serde_yml::from_str(content).map_err(|e| Error::Runtime {
        message: format!("invalid sandbox profile {}: {e}", source.display()),
    })?;
    validate(&profile, source)?;
    Ok(profile)
}

fn validate(profile: &SandboxProfile, source: &Path) -> Result<()> {
    if profile.version != PROFILE_SCHEMA_VERSION {
        return Err(Error::InvalidArgument(format!(
            "{} declares version {} but only {} is supported in this build",
            source.display(),
            profile.version,
            PROFILE_SCHEMA_VERSION
        )));
    }
    if profile.name.trim().is_empty() {
        return Err(Error::InvalidArgument(format!(
            "{}: profile name is empty",
            source.display()
        )));
    }
    // Phase 14 — `selinux_label` and `selinux_type` are mutually exclusive.
    // The static-label path skips the dynamic .te / checkmodule / semodule
    // pipeline entirely, so configuring both at once would silently throw away
    // the dynamic module. Reject up front with a clear error.
    if profile.selinux_label.is_some() && profile.selinux_type.is_some() {
        return Err(Error::InvalidArgument(format!(
            "{}: selinux_label and selinux_type are mutually exclusive — pick one (selinux_label for a static system label like \"container_t\", selinux_type when you want linpodx to synthesize a per-profile module)",
            source.display()
        )));
    }
    Ok(())
}

/// Scan `dir` for `*.yaml` files (one profile per file). Missing directory is **not** an
/// error — returns an empty Vec so users without any profiles can still use linpodx.
pub async fn load_profiles_from_dir(dir: &Path) -> Result<Vec<(SandboxProfile, String)>> {
    let mut out = Vec::new();
    let read_dir = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut read_dir = read_dir;
    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        if !is_yaml(&path) {
            continue;
        }
        let content = tokio::fs::read_to_string(&path).await?;
        let profile = parse_profile(&content, &path)?;
        out.push((profile, content));
    }
    out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    Ok(out)
}

fn is_yaml(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|s| s.to_str()),
        Some("yaml") | Some("yml")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_unknown_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        tokio::fs::write(&path, "version: 99\nname: future")
            .await
            .unwrap();
        let err = load_profile(&path).await.expect_err("should reject");
        match err {
            Error::InvalidArgument(_) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn loads_directory_and_skips_non_yaml() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("a.yaml"), "version: 1\nname: alpha")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("b.yml"), "version: 1\nname: beta")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("readme.md"), "# notes")
            .await
            .unwrap();
        let loaded = load_profiles_from_dir(dir.path()).await.unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].0.name, "alpha");
        assert_eq!(loaded[1].0.name, "beta");
    }

    #[tokio::test]
    async fn missing_directory_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let loaded = load_profiles_from_dir(&missing).await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn rejects_empty_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.yaml");
        tokio::fs::write(&path, "version: 1\nname: \"\"")
            .await
            .unwrap();
        assert!(load_profile(&path).await.is_err());
    }

    // ---- Phase 14: SELinux static-label / dynamic-type mutual exclusion ----

    #[tokio::test]
    async fn rejects_static_label_and_dynamic_type_together() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dual-se.yaml");
        tokio::fs::write(
            &path,
            "version: 1\nname: dual\nselinux_label: container_t\nselinux_type: linpodx_dual_t\n",
        )
        .await
        .unwrap();
        let err = load_profile(&path).await.expect_err("should reject");
        match err {
            Error::InvalidArgument(m) => {
                assert!(m.contains("selinux_label"), "got: {m}");
                assert!(m.contains("selinux_type"), "got: {m}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepts_only_static_label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("static-se.yaml");
        tokio::fs::write(
            &path,
            "version: 1\nname: static\nselinux_label: container_t\n",
        )
        .await
        .unwrap();
        let p = load_profile(&path).await.expect("load");
        assert_eq!(p.selinux_label.as_deref(), Some("container_t"));
        assert!(p.selinux_type.is_none());
    }

    #[tokio::test]
    async fn accepts_only_dynamic_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dyn-se.yaml");
        tokio::fs::write(
            &path,
            "version: 1\nname: dyn\nselinux_type: linpodx_dyn_t\n",
        )
        .await
        .unwrap();
        let p = load_profile(&path).await.expect("load");
        assert!(p.selinux_label.is_none());
        assert_eq!(p.selinux_type.as_deref(), Some("linpodx_dyn_t"));
    }
}
