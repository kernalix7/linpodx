//! Plugin manifest (`linpodx-plugin.toml`) parsing + on-disk install helper.
//!
//! Each plugin lives in its own directory. Two files are required:
//! * `linpodx-plugin.toml` — the manifest (this struct)
//! * the wasm binary referenced by `wasm = "..."` in the manifest
//!
//! Install copies the directory to `~/.local/share/linpodx/plugins/<name>/` (overridable
//! through `LINPODX_PLUGIN_DIR`) so the daemon has a stable absolute path.

use crate::{PluginError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MANIFEST_FILENAME: &str = "linpodx-plugin.toml";
const KNOWN_HOOKS: &[&str] = &[
    "approval",
    "audit_filter",
    "profile_validator",
    "network_trace",
    "runtime_injector",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub hooks: Vec<String>,
    pub wasm: String,
    /// Optional publisher identifier. When set, the sandbox install path looks up a
    /// matching public key in the trusted-keys registry by file stem (e.g. `acme` →
    /// `<keys_dir>/acme.pem`). Phase 15 — plugin signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Optional base64-encoded raw 64-byte ed25519 signature over the wasm binary.
    /// Used as a fallback when neither `PluginInstallParams.signature_path` nor a
    /// detached `signature.b64` next to the manifest is supplied. Phase 15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
}

impl PluginManifest {
    /// Validates `name` is non-empty, `hooks` contains at least one known hook, and
    /// `wasm` is a relative file name (no `..` traversal, no absolute paths). Called
    /// after TOML deserialization.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(PluginError::Manifest("name must not be empty".into()));
        }
        if self.version.trim().is_empty() {
            return Err(PluginError::Manifest("version must not be empty".into()));
        }
        if self.wasm.trim().is_empty() {
            return Err(PluginError::Manifest("wasm path must not be empty".into()));
        }
        let wasm_path = Path::new(&self.wasm);
        if wasm_path.is_absolute()
            || wasm_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(PluginError::Manifest(format!(
                "wasm path '{}' must be a relative file inside the plugin dir",
                self.wasm
            )));
        }
        if self.hooks.is_empty() {
            return Err(PluginError::Manifest(
                "hooks must list at least one hook".into(),
            ));
        }
        for h in &self.hooks {
            if !KNOWN_HOOKS.contains(&h.as_str()) {
                return Err(PluginError::Manifest(format!(
                    "unknown hook '{h}' (known: {:?})",
                    KNOWN_HOOKS
                )));
            }
        }
        Ok(())
    }
}

/// Parse `<dir>/linpodx-plugin.toml`, validate, and resolve the wasm path to an absolute
/// canonical path inside `<dir>`.
pub fn parse_from_dir(dir: &Path) -> Result<(PluginManifest, PathBuf)> {
    let manifest_path = dir.join(MANIFEST_FILENAME);
    let raw = std::fs::read_to_string(&manifest_path).map_err(|e| {
        PluginError::Manifest(format!("could not read {}: {e}", manifest_path.display()))
    })?;
    let manifest: PluginManifest =
        toml::from_str(&raw).map_err(|e| PluginError::Manifest(e.to_string()))?;
    manifest.validate()?;

    let wasm_abs = dir.join(&manifest.wasm);
    if !wasm_abs.is_file() {
        return Err(PluginError::Manifest(format!(
            "wasm file '{}' not found",
            wasm_abs.display()
        )));
    }
    Ok((manifest, wasm_abs))
}

/// User-level plugin install dir. Resolution order:
/// 1. `$LINPODX_PLUGIN_DIR` (set by tests / packaging)
/// 2. `$XDG_DATA_HOME/linpodx/plugins`
/// 3. `$HOME/.local/share/linpodx/plugins`
pub fn user_plugin_root() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("LINPODX_PLUGIN_DIR") {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("XDG_DATA_HOME") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p).join("linpodx").join("plugins"));
        }
    }
    let home = std::env::var("HOME")
        .map_err(|_| PluginError::Manifest("HOME not set; cannot locate plugin dir".into()))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("linpodx")
        .join("plugins"))
}

/// Copy `src_dir` to `<plugin_root>/<name>/` and re-parse the manifest from the install
/// location so callers receive absolute paths suitable for storing in SQLite.
pub fn install_to_user_dir(src_dir: &Path) -> Result<(PathBuf, PluginManifest, PathBuf)> {
    let (manifest, _wasm_in_src) = parse_from_dir(src_dir)?;
    let root = user_plugin_root()?;
    let dest = root.join(&manifest.name);
    if dest.exists() {
        return Err(PluginError::Duplicate(manifest.name.clone()));
    }
    std::fs::create_dir_all(&dest)?;
    copy_dir_recursive(src_dir, &dest)?;
    let (installed_manifest, wasm_abs) = parse_from_dir(&dest)?;
    Ok((dest, installed_manifest, wasm_abs))
}

/// Remove `<plugin_root>/<name>/`. No-op if the directory is already gone.
pub fn remove_user_dir(name: &str) -> Result<bool> {
    let dest = user_plugin_root()?.join(name);
    if !dest.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dest)?;
    Ok(true)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ft.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to)?;
        }
        // Symlinks intentionally skipped — plugins ship as plain files.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that mutate `LINPODX_PLUGIN_DIR` since env vars are process-wide.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn write_manifest(dir: &Path, body: &str) {
        std::fs::write(dir.join(MANIFEST_FILENAME), body).expect("write manifest");
    }

    fn write_dummy_wasm(dir: &Path, name: &str) {
        // 4 bytes magic + 4 bytes version. Enough to satisfy is_file checks; loader tests
        // that need a real module use a pre-built binary (see #[ignore] e2e).
        let bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        std::fs::write(dir.join(name), bytes).expect("write wasm");
    }

    #[test]
    fn parses_valid_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(
            tmp.path(),
            r#"
name = "demo"
version = "0.1.0"
hooks = ["approval"]
wasm = "demo.wasm"
"#,
        );
        write_dummy_wasm(tmp.path(), "demo.wasm");
        let (m, abs) = parse_from_dir(tmp.path()).expect("parse");
        assert_eq!(m.name, "demo");
        assert_eq!(m.version, "0.1.0");
        assert_eq!(m.hooks, vec!["approval".to_string()]);
        assert_eq!(abs, tmp.path().join("demo.wasm"));
    }

    #[test]
    fn rejects_unknown_hook() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(
            tmp.path(),
            r#"
name = "demo"
version = "0.1.0"
hooks = ["nonsense"]
wasm = "demo.wasm"
"#,
        );
        write_dummy_wasm(tmp.path(), "demo.wasm");
        let err = parse_from_dir(tmp.path()).unwrap_err();
        assert!(matches!(err, PluginError::Manifest(_)));
    }

    #[test]
    fn rejects_traversal_wasm_path() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(
            tmp.path(),
            r#"
name = "demo"
version = "0.1.0"
hooks = ["approval"]
wasm = "../escape.wasm"
"#,
        );
        let err = parse_from_dir(tmp.path()).unwrap_err();
        assert!(matches!(err, PluginError::Manifest(_)));
    }

    #[test]
    fn rejects_missing_wasm_file() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(
            tmp.path(),
            r#"
name = "demo"
version = "0.1.0"
hooks = ["approval"]
wasm = "missing.wasm"
"#,
        );
        let err = parse_from_dir(tmp.path()).unwrap_err();
        assert!(matches!(err, PluginError::Manifest(_)));
    }

    #[test]
    fn install_copies_then_rejects_duplicate() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let src = tempfile::tempdir().unwrap();
        let install_root = tempfile::tempdir().unwrap();
        std::env::set_var("LINPODX_PLUGIN_DIR", install_root.path());

        write_manifest(
            src.path(),
            r#"
name = "copy-me"
version = "0.2.0"
hooks = ["approval"]
wasm = "copy.wasm"
"#,
        );
        write_dummy_wasm(src.path(), "copy.wasm");

        let (dest, manifest, wasm_abs) = install_to_user_dir(src.path()).expect("install");
        assert_eq!(manifest.name, "copy-me");
        assert!(dest.starts_with(install_root.path()));
        assert!(wasm_abs.is_file());

        // Second install fails with Duplicate.
        let err = install_to_user_dir(src.path()).unwrap_err();
        assert!(matches!(err, PluginError::Duplicate(n) if n == "copy-me"));

        // Remove cleans up.
        let removed = remove_user_dir("copy-me").expect("remove");
        assert!(removed);
        let removed_again = remove_user_dir("copy-me").expect("remove again");
        assert!(!removed_again);

        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }
}
