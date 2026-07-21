//! Shared helpers for reading/writing sandbox-profile YAML from the CLI side.
//!
//! Both `linpodx passthrough <...>` (commands::passthrough) and
//! `linpodx network egress <...>` (commands::network) mutate a profile's YAML
//! document client-side (fetch → patch a field → write to disk → ask the
//! daemon to reload) rather than going through a dedicated IPC method. These
//! helpers centralise that round-trip so the two callers stay in lockstep.
#![forbid(unsafe_code)]

use crate::client::Client;
use anyhow::{Context, Result};
use linpodx_common::ipc::{Method, SandboxProfileNameParams};
use linpodx_common::passthrough::PassthroughSpec;
use std::path::{Path, PathBuf};

/// Fetch a sandbox profile's YAML from the daemon and parse it into a mutable
/// `serde_norway::Value` tree.
pub(crate) async fn fetch_profile_yaml(
    client: &mut Client,
    profile: &str,
) -> Result<serde_norway::Value> {
    use linpodx_common::ipc::responses::SandboxProfileGetResponse;
    let resp: SandboxProfileGetResponse = client
        .call(Method::SandboxProfileGet(SandboxProfileNameParams {
            name: profile.to_string(),
        }))
        .await
        .with_context(|| format!("fetching profile '{profile}'"))?;
    let value: serde_norway::Value = serde_norway::from_str(&resp.yaml)
        .with_context(|| format!("parsing profile '{profile}' as YAML"))?;
    Ok(value)
}

pub(crate) fn read_passthrough_field(value: &serde_norway::Value) -> PassthroughSpec {
    value
        .get("passthrough")
        .and_then(|v| serde_norway::from_value::<PassthroughSpec>(v.clone()).ok())
        .unwrap_or_default()
}

pub(crate) fn write_passthrough_field(
    value: &mut serde_norway::Value,
    spec: Option<&PassthroughSpec>,
) {
    let mapping = match value.as_mapping_mut() {
        Some(m) => m,
        None => return,
    };
    let key = serde_norway::Value::String("passthrough".into());
    match spec {
        Some(s) => {
            if let Ok(v) = serde_norway::to_value(s) {
                mapping.insert(key, v);
            }
        }
        None => {
            mapping.remove(&key);
        }
    }
}

pub(crate) fn default_profiles_dir() -> PathBuf {
    if let Ok(d) = std::env::var("LINPODX_SANDBOX_PROFILES_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("linpodx").join("profiles")
}

pub(crate) async fn persist_profile_and_reload(
    client: &mut Client,
    profile: &str,
    profiles_dir_override: Option<&Path>,
    value: &serde_norway::Value,
) -> Result<()> {
    let dir = profiles_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(default_profiles_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating profiles dir {}", dir.display()))?;

    let yaml = serde_norway::to_string(value).context("re-serializing profile YAML")?;
    let target = pick_profile_path(&dir, profile);
    std::fs::write(&target, yaml).with_context(|| format!("writing {}", target.display()))?;

    use linpodx_common::ipc::responses::SandboxProfileReloadResponse;
    let _ack: SandboxProfileReloadResponse = client.call(Method::SandboxProfileReload).await?;
    Ok(())
}

pub(crate) fn pick_profile_path(dir: &Path, profile: &str) -> PathBuf {
    for ext in ["yaml", "yml"] {
        let candidate = dir.join(format!("{profile}.{ext}"));
        if candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{profile}.yaml"))
}
