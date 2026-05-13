//! Generate `~/.local/share/applications/linpodx-<name>.desktop` so distro instances
//! show up in the host application menu.
//!
//! The file location is chosen via `$XDG_DATA_HOME/applications` if set, else
//! `$HOME/.local/share/applications`. We deliberately avoid pulling in the `dirs` crate
//! to keep the dep graph small.

use crate::{DistroError, Result};
use std::path::{Path, PathBuf};

/// Default applications directory.
pub fn applications_dir() -> Result<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("applications"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| {
        DistroError::Runtime(
            "HOME env var not set; cannot locate ~/.local/share/applications".into(),
        )
    })?;
    Ok(PathBuf::from(home).join(".local/share/applications"))
}

/// Render the `.desktop` file body. Pure function for tests.
pub fn render_desktop_entry(name: &str, exec_cmd: &[String], icon: Option<&Path>) -> String {
    let exec_str = shell_quote_cmd(exec_cmd);
    let icon_line = icon
        .map(|p| format!("Icon={}\n", p.display()))
        .unwrap_or_default();
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=linpodx: {name}\n\
         Comment=linpodx distro instance '{name}'\n\
         Exec={exec_str}\n\
         {icon_line}\
         Terminal=true\n\
         Categories=System;Utility;\n\
         X-Linpodx-Instance={name}\n"
    )
}

/// Write the `.desktop` entry to disk and return the resulting path.
pub fn write_desktop_entry(
    name: &str,
    exec_cmd: &[String],
    icon: Option<&Path>,
) -> Result<PathBuf> {
    if name.is_empty() {
        return Err(DistroError::Runtime(
            "instance name must not be empty".into(),
        ));
    }
    let dir = applications_dir()?;
    std::fs::create_dir_all(&dir).map_err(DistroError::Io)?;
    let body = render_desktop_entry(name, exec_cmd, icon);
    let path = dir.join(format!("linpodx-{name}.desktop"));
    std::fs::write(&path, body).map_err(DistroError::Io)?;
    Ok(path)
}

/// Remove the `.desktop` entry for an instance. `Ok(false)` if the file did not exist.
pub fn remove_desktop_entry(name: &str) -> Result<bool> {
    let dir = applications_dir()?;
    let path = dir.join(format!("linpodx-{name}.desktop"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(DistroError::Io(e)),
    }
}

fn shell_quote_cmd(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            if p.chars()
                .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'))
            {
                let escaped = p.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{escaped}\"")
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // env-var mutation tests must serialize so they don't race each other when the test
    // runner uses multiple threads (the default).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn render_simple_entry() {
        let s = render_desktop_entry(
            "alpine-dev",
            &[
                "podman".into(),
                "exec".into(),
                "-it".into(),
                "linpodx-distro-alpine-dev".into(),
                "ash".into(),
            ],
            None,
        );
        assert!(s.contains("[Desktop Entry]"));
        assert!(s.contains("Name=linpodx: alpine-dev"));
        assert!(s.contains("Exec=podman exec -it linpodx-distro-alpine-dev ash"));
        assert!(s.contains("X-Linpodx-Instance=alpine-dev"));
        assert!(!s.contains("Icon="));
        assert!(s.contains("Terminal=true"));
    }

    #[test]
    fn render_with_icon() {
        let s = render_desktop_entry(
            "fed",
            &["true".into()],
            Some(Path::new("/usr/share/icons/hicolor/48x48/apps/fedora.png")),
        );
        assert!(s.contains("Icon=/usr/share/icons/hicolor/48x48/apps/fedora.png"));
    }

    #[test]
    fn render_quotes_args_with_spaces() {
        let s = render_desktop_entry(
            "x",
            &["sh".into(), "-c".into(), "echo hello world".into()],
            None,
        );
        assert!(s.contains("Exec=sh -c \"echo hello world\""));
    }

    #[test]
    fn write_and_remove_desktop_entry_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_DATA_HOME", tmp.path());

        let path = write_desktop_entry("test-inst", &["echo".into(), "hi".into()], None).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("X-Linpodx-Instance=test-inst"));

        assert!(remove_desktop_entry("test-inst").unwrap());
        assert!(!path.exists());
        assert!(!remove_desktop_entry("test-inst").unwrap());

        std::env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    fn applications_dir_prefers_xdg_data_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("XDG_DATA_HOME", "/tmp/xdg-test-data-home");
        let dir = applications_dir().unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/xdg-test-data-home/applications"));
        std::env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    fn write_rejects_empty_name() {
        let err = write_desktop_entry("", &["true".into()], None).unwrap_err();
        assert!(matches!(err, DistroError::Runtime(_)));
    }
}
