//! Tiny WebSocket helper used by every panel: open `/ipc`, send a Subscribe
//! request for a single topic, and pump notifications back out via a callback.
//!
//! The daemon expects every IPC frame to carry a bearer token; for the WebSocket
//! upgrade the browser API doesn't let us set arbitrary headers, so Phase 10
//! added a `?token=<t>` query string path on the daemon's `/ipc` route. We
//! always append it when a token is present in `localStorage` so the daemon
//! can authenticate without waiting on the first-frame envelope.
//!
//! Security note: the query string can land in TLS-terminating proxy access
//! logs and browser history. For untrusted networks pair this with mTLS.

use futures::{SinkExt, StreamExt};
use gloo_net::http::Request;
use gloo_net::websocket::{futures::WebSocket, Message};
use gloo_storage::Storage;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

const TOKEN_KEY: &str = "linpodx_token";

/// Fetch a JSON list from `/api/v1/<path>` with a bearer token.
///
/// Returns the decoded JSON value (typically an array). On any failure the
/// caller gets `Err(message)` for display.
pub async fn fetch_list(path: &str, token: &str) -> Result<Value, String> {
    let url = format!("/api/v1/{path}");
    let resp = Request::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("fetch error: {e}"))?;
    if !resp.ok() {
        return Err(format!("http {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Open `/ipc`, send a Subscribe for one topic, and invoke `on_event` for every
/// `event` notification we receive. The connection lives until the page is
/// unloaded; failures are logged but never panic.
pub fn subscribe<F>(topic: &'static str, mut on_event: F)
where
    F: FnMut(Value) + 'static,
{
    let location = match web_sys::window().and_then(|w| w.location().host().ok()) {
        Some(h) => h,
        None => return,
    };
    let proto = match web_sys::window()
        .and_then(|w| w.location().protocol().ok())
        .as_deref()
    {
        Some("https:") => "wss",
        _ => "ws",
    };
    let token = gloo_storage::LocalStorage::get::<String>(TOKEN_KEY)
        .ok()
        .filter(|s| !s.trim().is_empty());
    let url = match token.as_deref() {
        Some(t) => format!("{proto}://{location}/ipc?token={}", url_encode_component(t)),
        None => format!("{proto}://{location}/ipc"),
    };

    let ws = match WebSocket::open(&url) {
        Ok(w) => w,
        Err(e) => {
            web_sys::console::warn_1(&format!("ws open failed: {e:?}").into());
            return;
        }
    };

    spawn_local(async move {
        let (mut tx, mut rx) = ws.split();
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "subscribe",
            "params": { "topics": [topic] },
        });
        let payload = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(e) => {
                web_sys::console::warn_1(&format!("ws encode failed: {e}").into());
                return;
            }
        };
        if let Err(e) = tx.send(Message::Text(payload)).await {
            web_sys::console::warn_1(&format!("ws send failed: {e}").into());
            return;
        }

        while let Some(msg) = rx.next().await {
            let text = match msg {
                Ok(Message::Text(t)) => t,
                Ok(Message::Bytes(_)) => continue,
                Err(e) => {
                    web_sys::console::warn_1(&format!("ws recv error: {e}").into());
                    break;
                }
            };
            let v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // We only forward server-pushed notifications (no `id`, has `method`).
            if v.get("id").is_none() && v.get("method").and_then(|m| m.as_str()).is_some() {
                on_event(v);
            }
        }
    });
}

/// One-shot JSON-RPC call over the existing `/ipc` WebSocket. Opens a fresh
/// socket, sends `{method, params}` as `request_id = 1`, and resolves with the
/// matching response (or an error string for transport / RPC failures).
///
/// Used by panels that need to trigger a write action (e.g. Images "Push").
/// The websocket is closed after the response — we don't pool them.
pub async fn send_rpc(method: &str, params: Value) -> Result<Value, String> {
    let location = web_sys::window()
        .and_then(|w| w.location().host().ok())
        .ok_or_else(|| "no window/location".to_string())?;
    let proto = match web_sys::window()
        .and_then(|w| w.location().protocol().ok())
        .as_deref()
    {
        Some("https:") => "wss",
        _ => "ws",
    };
    let token = gloo_storage::LocalStorage::get::<String>(TOKEN_KEY)
        .ok()
        .filter(|s| !s.trim().is_empty());
    let url = match token.as_deref() {
        Some(t) => format!("{proto}://{location}/ipc?token={}", url_encode_component(t)),
        None => format!("{proto}://{location}/ipc"),
    };

    let ws = WebSocket::open(&url).map_err(|e| format!("ws open failed: {e:?}"))?;
    let (mut tx, mut rx) = ws.split();
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let payload = serde_json::to_string(&req).map_err(|e| format!("encode error: {e}"))?;
    tx.send(Message::Text(payload))
        .await
        .map_err(|e| format!("ws send failed: {e}"))?;

    while let Some(msg) = rx.next().await {
        let text = match msg {
            Ok(Message::Text(t)) => t,
            Ok(Message::Bytes(_)) => continue,
            Err(e) => return Err(format!("ws recv error: {e}")),
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Skip unrelated server-pushed notifications; only the matching response
        // (id == 1) terminates the call.
        if v.get("id").and_then(|i| i.as_i64()) != Some(1) {
            continue;
        }
        if let Some(err) = v.get("error") {
            return Err(format!("rpc error: {err}"));
        }
        return Ok(v.get("result").cloned().unwrap_or(Value::Null));
    }
    Err("ws closed before response".into())
}

/// Percent-encode a token for use as a query string value. Mirrors the
/// JS `encodeURIComponent` charset (alnum, `-_.~` left intact, everything
/// else escaped). We avoid pulling in a full `url` crate just for this.
fn url_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.as_bytes() {
        let c = *b;
        let safe = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}
