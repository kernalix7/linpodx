//! Phase 24 — local (loopback) plaintext Web UI listener for the desktop shell.
//!
//! The desktop app (`linpodx-gui`) is a thin Tauri window that displays the
//! daemon-served leptos Web UI. To reach it the shell issues a `WebUiEnsure`
//! IPC; on the **first** call the daemon binds a fresh plaintext HTTP listener
//! on `127.0.0.1:0` (an ephemeral loopback port), mints a random
//! per-daemon-lifetime bearer token, and serves the SAME axum router surface
//! the remote WebSocket listener uses (`/api/v1/*`, `/ui/*`, and the PTY
//! WebSocket `/pty/:bridge_id`) by reusing [`crate::remote::spawn`] with TLS +
//! client-pinning disabled. The `(url, token)` pair and the owning
//! [`RemoteHandle`] are cached so every later call returns the same values with
//! `started = false`.
//!
//! This listener is deliberately **independent** of `--remote-listen`, which may
//! terminate TLS and/or require mTLS. The local listener is always plaintext and
//! always loopback-only — it exists purely so a same-host webview can load the
//! UI without a certificate dance. It never terminates TLS here.

use crate::dispatch::Dispatcher;
use crate::remote::{self, RemoteHandle};
use linpodx_common::audit_sink::AuditSinkKind;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::WebUiEnsureResponse;
use rand::Rng;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::info;

/// The stable coordinates of the running local listener.
#[derive(Clone, Debug)]
pub(crate) struct Coords {
    pub url: String,
    pub token: String,
}

/// Cached local-listener state. Owning the [`RemoteHandle`] keeps the background
/// serve task + cancellation token alive for the daemon's lifetime; dropping it
/// (daemon shutdown) tears the listener down cleanly.
pub struct WebUiLocalHandle {
    coords: Coords,
    // Held only to own the listener; never read after construction.
    _remote: RemoteHandle,
}

/// Ensure the loopback Web UI listener is running and return its coordinates.
///
/// Idempotent: the first call binds + spawns and returns `started = true`; every
/// subsequent call returns the cached `url` / `token` with `started = false`.
/// The cache mutex is held across the (synchronous) bind so two concurrent
/// callers can never race two listeners into existence.
pub async fn ensure(dispatcher: &Dispatcher) -> Result<WebUiEnsureResponse> {
    let mut slot = dispatcher.web_ui_local.lock().await;
    if let Some(existing) = slot.as_ref() {
        return Ok(cached_response(&existing.coords));
    }

    let token = random_token();
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    // `remote::spawn` needs an owned `Arc<Dispatcher>`; the dispatcher is cheap
    // to clone (all fields are `Arc`s) and the clone shares the same subsystems.
    let inner = Arc::new(dispatcher.clone());
    let handle = remote::spawn(
        bind,
        token.clone(),
        inner,
        Arc::clone(&dispatcher.audit),
        None,  // plaintext — never TLS on the local listener
        false, // no client-cert pinning on loopback
    )
    .map_err(|e| Error::Runtime {
        message: format!("local web UI bind failed: {e}"),
    })?;

    let coords = Coords {
        url: local_url(handle.state.addr),
        token,
    };
    info!(url = %coords.url, "local Web UI listener started for desktop shell");
    dispatcher
        .audit
        .record(
            AuditSinkKind::WebUiSessionStarted,
            None,
            None,
            json!({ "local": true, "addr": handle.state.addr.to_string() }),
        )
        .await;

    let response = started_response(&coords);
    *slot = Some(WebUiLocalHandle {
        coords,
        _remote: handle,
    });
    Ok(response)
}

/// Response for the call that actually started the listener (`started = true`).
fn started_response(c: &Coords) -> WebUiEnsureResponse {
    WebUiEnsureResponse {
        url: c.url.clone(),
        token: c.token.clone(),
        started: true,
    }
}

/// Response for a call that reused an already-running listener
/// (`started = false`, url/token unchanged).
pub(crate) fn cached_response(c: &Coords) -> WebUiEnsureResponse {
    WebUiEnsureResponse {
        url: c.url.clone(),
        token: c.token.clone(),
        started: false,
    }
}

/// `http://host:port` for the bound listener. Always plaintext HTTP — the local
/// listener never terminates TLS. `SocketAddr`'s `Display` brackets IPv6 hosts
/// so the result is always a valid URL authority.
fn local_url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

/// 128-bit random hex token, unique per daemon lifetime. Uses the workspace
/// `rand` std RNG rather than a hand-rolled generator.
fn random_token() -> String {
    let mut rng = rand::thread_rng();
    let hi: u64 = rng.gen();
    let lo: u64 = rng.gen();
    format!("{hi:016x}{lo:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn local_url_formats_ipv4_as_http() {
        let addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 53187));
        assert_eq!(local_url(addr), "http://127.0.0.1:53187");
    }

    #[test]
    fn local_url_brackets_ipv6_host() {
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 8080));
        // SocketAddr Display brackets the v6 host, keeping the URL authority valid.
        assert_eq!(local_url(addr), "http://[::1]:8080");
    }

    #[test]
    fn random_token_is_32_lowercase_hex() {
        let t = random_token();
        assert_eq!(t.len(), 32, "expected a 128-bit token as 32 hex chars");
        assert!(
            t.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "token must be lowercase hex: {t}"
        );
    }

    #[test]
    fn random_token_differs_between_calls() {
        // Collision probability at 128 bits is negligible; this guards against a
        // constant/hard-coded token regression.
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b, "each daemon-lifetime token must be freshly random");
    }

    #[test]
    fn cached_response_is_stable_and_not_started() {
        // Idempotence + token stability: reusing the same coordinates yields an
        // identical url/token with `started = false`.
        let c = Coords {
            url: "http://127.0.0.1:40000".to_string(),
            token: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        };
        let first = cached_response(&c);
        let second = cached_response(&c);
        assert_eq!(first.url, "http://127.0.0.1:40000");
        assert_eq!(first.token, c.token);
        assert!(!first.started);
        assert_eq!(first.url, second.url);
        assert_eq!(first.token, second.token);
        assert!(!second.started);
    }

    #[test]
    fn started_response_flags_started_true() {
        let c = Coords {
            url: "http://127.0.0.1:1".to_string(),
            token: "t".to_string(),
        };
        let r = started_response(&c);
        assert!(r.started);
        assert_eq!(r.url, c.url);
        assert_eq!(r.token, c.token);
    }
}
