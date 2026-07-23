//! Podman secret wrappers (Phase 26 — secrets management, issue #9).
//!
//! Wraps `podman secret {ls,create,rm}`. The plaintext secret value is
//! **never** passed on the command line (it would leak into `/proc/<pid>/cmdline`
//! for any other user on the host) — `podman secret create <name> -` reads the
//! value from stdin instead. Callers (the daemon dispatch layer) must also
//! never log or audit the value; only the secret `name` is safe to record.

use crate::podman::Podman;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::SecretSummary;
use serde_json::Value;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tracing::{debug, instrument};

/// `podman secret ls` does not honor the usual `--format json` array shortcut
/// (it prints the literal string `json`, treating it as an unknown Go
/// template). Use `--format '{{json .}}'` instead, which prints one JSON
/// object per line (JSON Lines, not a JSON array).
const LIST_FORMAT: &str = "{{json .}}";

fn looks_like_secret_not_found(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no such secret") || lower.contains("no secret with name")
}

#[instrument(skip(podman))]
pub async fn list(podman: &Podman) -> Result<Vec<SecretSummary>> {
    let mut cmd = podman.base_command();
    cmd.arg("secret").arg("ls").arg("--format").arg(LIST_FORMAT);
    let out = podman.run_capture(cmd).await?;
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(parse_secret_summary_line)
        .collect()
}

fn parse_secret_summary_line(line: &str) -> Result<SecretSummary> {
    let v: Value = serde_json::from_str(line).map_err(|e| Error::Runtime {
        message: format!("failed to parse `podman secret ls` line: {e}"),
    })?;
    let id = v
        .get("ID")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "secret ls row missing ID".into(),
        })?
        .to_string();
    let name = v
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Runtime {
            message: "secret ls row missing Name".into(),
        })?
        .to_string();
    // NOTE: `podman secret ls` reports `CreatedAt` as a human-relative string
    // (e.g. "12 seconds ago"), not RFC3339 — passed through verbatim since
    // `SecretSummary.created` is an opaque display string.
    let created = v
        .get("CreatedAt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let driver = v
        .get("Driver")
        .and_then(Value::as_str)
        .unwrap_or("file")
        .to_string();
    Ok(SecretSummary {
        id,
        name,
        created,
        driver,
    })
}

/// Creates a podman secret. The value is piped over stdin — it never appears
/// in `cmd`'s argv, so it never leaks into `/proc/<pid>/cmdline` or process
/// listings. Returns the new secret's id.
#[instrument(skip(podman, value))]
pub async fn create(podman: &Podman, name: &str, value: &str) -> Result<String> {
    let mut cmd = podman.base_command();
    cmd.arg("secret")
        .arg("create")
        .arg(name)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    debug!(secret_name = name, "podman secret create (value redacted)");
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| Error::Runtime {
        message: "failed to open stdin for podman secret create".into(),
    })?;
    stdin.write_all(value.as_bytes()).await?;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(Error::Runtime { message: stderr });
    }
    let id = String::from_utf8(output.stdout)
        .map_err(|e| Error::Runtime {
            message: e.to_string(),
        })?
        .trim()
        .to_string();
    if id.is_empty() {
        return Err(Error::Runtime {
            message: "podman secret create returned empty id".into(),
        });
    }
    Ok(id)
}

#[instrument(skip(podman))]
pub async fn remove(podman: &Podman, name: &str) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("secret").arg("rm").arg(name);
    match podman.run_capture(cmd).await {
        Ok(_) => Ok(()),
        Err(Error::Runtime { message }) if looks_like_secret_not_found(&message) => {
            Err(Error::NotFound(name.to_string()))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secret_ls_json_line() {
        let line = r#"{"ID":"63712b6f299dc1ba2dc59b591","Name":"demo-secret","Driver":"file","CreatedAt":"5 seconds ago","UpdatedAt":"5 seconds ago"}"#;
        let s = parse_secret_summary_line(line).unwrap();
        assert_eq!(s.id, "63712b6f299dc1ba2dc59b591");
        assert_eq!(s.name, "demo-secret");
        assert_eq!(s.driver, "file");
        assert_eq!(s.created, "5 seconds ago");
    }

    #[test]
    fn rejects_malformed_line() {
        let err = parse_secret_summary_line("not json").unwrap_err();
        assert!(matches!(err, Error::Runtime { .. }));
    }

    #[test]
    fn detects_not_found_message() {
        assert!(looks_like_secret_not_found(
            "Error: no secret with name or id \"x\": no such secret"
        ));
        assert!(!looks_like_secret_not_found("Error: permission denied"));
    }
}
