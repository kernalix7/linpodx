//! Phase 24 (Tauri pivot) — desktop-shell glue logic.
//!
//! Pure, Qt-free helpers plus the async "make the daemon-served Web UI
//! reachable" flow used by the Tauri entrypoint:
//!
//! 1. probe the daemon Unix socket (via [`linpodx_gui_core::connection::one_shot`]);
//! 2. if it is dead, auto-spawn `linpodx-daemon --fork` the same way the CLI
//!    does (binary next to `current_exe`, then `$PATH`; detached; poll the
//!    socket for up to ~10 s);
//! 3. call [`Method::WebUiEnsure`] to bind/return the loopback Web UI listener;
//! 4. hand back `<url>/ui/?token=<token>` for the webview to navigate to.
//!
//! All fallible steps return `anyhow::Result`; there are no `unwrap`/`expect`
//! calls outside tests.

use anyhow::{bail, Context, Result};
use linpodx_common::ipc::responses::{VersionResponse, WebUiEnsureResponse};
use linpodx_common::ipc::{Method, WebUiEnsureParams};
use linpodx_gui_core::connection::one_shot;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{info, warn};

/// How long to wait for an auto-spawned daemon to create its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve the daemon socket path the same way `linpodx-daemon` does: honour
/// `LINPODX_SOCKET`, else `$XDG_RUNTIME_DIR/linpodx.sock`, else
/// `/tmp/linpodx-$UID.sock`.
pub fn socket_path() -> PathBuf {
    if let Some(s) = std::env::var_os("LINPODX_SOCKET") {
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
    default_socket_path()
}

/// `$XDG_RUNTIME_DIR/linpodx.sock` falling back to `/tmp/linpodx-$UID.sock`.
pub fn default_socket_path() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("linpodx.sock");
        }
    }
    PathBuf::from(format!("/tmp/linpodx-{}.sock", current_uid()))
}

/// `$XDG_RUNTIME_DIR/linpodx.pid` falling back to `/tmp/linpodx-$UID.pid`.
/// Mirrors the CLI + daemon defaults so all three agree.
pub fn default_pid_file() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("linpodx.pid");
        }
    }
    PathBuf::from(format!("/tmp/linpodx-{}.pid", current_uid()))
}

/// `$XDG_STATE_HOME/linpodx/daemon.log` falling back to
/// `$HOME/.local/state/linpodx/daemon.log` then `/tmp/linpodx-$UID/daemon.log`.
pub fn default_log_file() -> PathBuf {
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        if !state.is_empty() {
            return PathBuf::from(state).join("linpodx").join("daemon.log");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("linpodx")
                .join("daemon.log");
        }
    }
    PathBuf::from(format!("/tmp/linpodx-{}/daemon.log", current_uid()))
}

/// Ordered candidate list for the `linpodx-daemon` binary, highest priority
/// first: explicit `$LINPODX_DAEMON_BIN`, a sibling of the running shell binary,
/// then a bare `linpodx-daemon` (resolved via `$PATH` by the OS at spawn time).
/// Kept pure (no filesystem probing) so it is unit-testable.
pub fn daemon_binary_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(env) = std::env::var_os("LINPODX_DAEMON_BIN") {
        if !env.is_empty() {
            out.push(PathBuf::from(env));
        }
    }
    if let Ok(self_path) = std::env::current_exe() {
        if let Some(dir) = self_path.parent() {
            out.push(dir.join("linpodx-daemon"));
        }
    }
    out.push(PathBuf::from("linpodx-daemon"));
    out
}

/// Pick the first candidate that exists on disk, falling back to the last
/// (bare-name) entry so the OS can resolve it via `$PATH`. Never fails —
/// worst case returns `linpodx-daemon`.
pub fn resolve_daemon_binary() -> PathBuf {
    let candidates = daemon_binary_candidates();
    for c in &candidates {
        // The bare-name last entry has no parent-relative existence check; only
        // treat path-qualified candidates as "found" when present on disk.
        if c.components().count() > 1 && c.exists() {
            return c.clone();
        }
    }
    candidates
        .into_iter()
        .last()
        .unwrap_or_else(|| PathBuf::from("linpodx-daemon"))
}

/// Build the webview navigation target from the daemon's `WebUiEnsure` reply.
/// The token rides in the query string so the browser `fetch()` / WebSocket
/// auth paths pick it up (the daemon accepts `?token=` on both).
///
/// No trailing slash after `/ui`: the daemon's static router answers `/ui`
/// but 404s `/ui/` (axum nest semantics), so the slashed form would open the
/// webview on an error page.
pub fn ui_url(base: &str, token: &str) -> String {
    format!("{}/ui?token={}", base.trim_end_matches('/'), token)
}

/// Full flow: ensure the daemon is reachable (auto-spawning if needed), then
/// ask it for the loopback Web UI listener and return the navigation URL.
pub async fn ensure_ui_url() -> Result<String> {
    let socket = socket_path();

    if daemon_alive(&socket).await {
        info!(socket = %socket.display(), "daemon already running");
    } else {
        info!(socket = %socket.display(), "daemon not reachable; auto-spawning");
        spawn_daemon(&socket)
            .await
            .context("auto-starting linpodx-daemon")?;
    }

    let resp: WebUiEnsureResponse =
        one_shot(&socket, Method::WebUiEnsure(WebUiEnsureParams::default()))
            .await
            .context("requesting local Web UI listener (WebUiEnsure)")?;
    info!(url = %resp.url, started = resp.started, "local Web UI listener ready");
    Ok(ui_url(&resp.url, &resp.token))
}

/// True when a `Version` ping over the socket succeeds.
async fn daemon_alive(socket: &Path) -> bool {
    one_shot::<VersionResponse>(socket, Method::Version)
        .await
        .is_ok()
}

/// Spawn `linpodx-daemon --fork --pid-file <pid>` detached (stdio → log file)
/// and wait up to [`SPAWN_TIMEOUT`] for the socket to appear. Mirrors the CLI's
/// `spawn_detached_daemon` auto-start path.
async fn spawn_daemon(socket: &Path) -> Result<()> {
    let binary = resolve_daemon_binary();
    let pid_file = default_pid_file();
    let log_file = default_log_file();
    if let Some(dir) = log_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .with_context(|| format!("opening daemon log file {}", log_file.display()))?;

    std::process::Command::new(&binary)
        .arg("--fork")
        .arg("--pid-file")
        .arg(&pid_file)
        .env("LINPODX_SOCKET", socket)
        .stdout(std::process::Stdio::from(log.try_clone()?))
        .stderr(std::process::Stdio::from(log))
        .stdin(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {} --fork", binary.display()))?;

    let start = std::time::Instant::now();
    while start.elapsed() < SPAWN_TIMEOUT {
        if socket.exists() {
            // Small grace so `listen()` is ready after `bind()`.
            tokio::time::sleep(Duration::from_millis(50)).await;
            if daemon_alive(socket).await {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    warn!(log = %log_file.display(), "auto-started daemon did not become ready in time");
    bail!(
        "auto-started daemon did not create a working socket at {} within {:?} (check {})",
        socket.display(),
        SPAWN_TIMEOUT,
        log_file.display()
    );
}

/// Real-uid from `/proc/self/status`, falling back to 1000. Avoids a `libc`
/// dependency just for `getuid()`; matches the CLI + daemon helpers.
fn current_uid() -> u32 {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s
            .lines()
            .find_map(|l| {
                l.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
            })
            .and_then(|n| n.parse().ok())
            .unwrap_or(1000),
        Err(_) => 1000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_url_appends_ui_path_and_token() {
        assert_eq!(
            ui_url("http://127.0.0.1:53187", "abc123"),
            "http://127.0.0.1:53187/ui?token=abc123"
        );
    }

    #[test]
    fn ui_url_trims_trailing_slash_on_base() {
        assert_eq!(
            ui_url("http://127.0.0.1:8080/", "tok"),
            "http://127.0.0.1:8080/ui?token=tok"
        );
    }

    #[test]
    fn default_socket_path_ends_in_linpodx_sock() {
        let p = default_socket_path();
        assert!(p.file_name().is_some_and(|n| n == "linpodx.sock"));
    }

    #[test]
    fn default_pid_file_ends_in_linpodx_pid() {
        let p = default_pid_file();
        assert!(p.file_name().is_some_and(|n| n == "linpodx.pid"));
    }

    #[test]
    fn default_log_file_ends_in_daemon_log_under_linpodx() {
        let p = default_log_file();
        assert!(p.file_name().is_some_and(|n| n == "daemon.log"));
        assert!(p.parent().is_some_and(|d| d.ends_with("linpodx")));
    }

    #[test]
    fn daemon_binary_candidates_end_with_bare_name() {
        // The last candidate is always the bare name so `$PATH` resolution
        // remains the final fallback regardless of env / current_exe state.
        let candidates = daemon_binary_candidates();
        assert_eq!(
            candidates.last().map(PathBuf::as_path),
            Some(Path::new("linpodx-daemon"))
        );
    }

    #[test]
    fn resolve_daemon_binary_never_empty() {
        // Even with nothing on disk the resolver yields the bare fallback.
        let b = resolve_daemon_binary();
        assert!(!b.as_os_str().is_empty());
    }
}
