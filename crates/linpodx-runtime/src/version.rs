use linpodx_common::error::{Error, Result};
use std::process::Stdio;
use tokio::process::Command;

/// Minimum supported Podman version. Bump deliberately and document the change in CHANGELOG.
pub const MIN_PODMAN_VERSION: &str = "4.6.0";

/// Query the installed Podman version. Returns the full semver string (e.g. `"5.8.1"`).
pub async fn podman_version(binary: &str) -> Result<String> {
    let mut cmd = Command::new(binary);
    cmd.arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let output = cmd.output().await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::PodmanNotFound(binary.to_string()),
        _ => Error::Io(e),
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(Error::Runtime {
            message: format!("podman --version failed: {stderr}"),
        });
    }

    // Output looks like: "podman version 5.8.1"
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v = stdout
        .split_whitespace()
        .last()
        .ok_or_else(|| Error::Runtime {
            message: "could not parse podman --version output".into(),
        })?
        .trim()
        .to_string();
    Ok(v)
}

/// Compare two dotted version strings (`major.minor.patch[-suffix]`). Suffix ignored.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> [u32; 3] {
        let mut out = [0u32; 3];
        for (i, p) in s.split('.').take(3).enumerate() {
            let n = p.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("0");
            out[i] = n.parse().unwrap_or(0);
        }
        out
    }
    parts(a).cmp(&parts(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        use std::cmp::Ordering;
        assert_eq!(compare_versions("5.8.1", "4.6.0"), Ordering::Greater);
        assert_eq!(compare_versions("4.6.0", "4.6.0"), Ordering::Equal);
        assert_eq!(compare_versions("4.5.0", "4.6.0"), Ordering::Less);
        assert_eq!(compare_versions("5.0.0-rc1", "4.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("4.6.0-dev", "4.6.0"), Ordering::Equal);
    }
}
