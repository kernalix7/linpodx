//! Phase 17 — REST wrappers for the four new endpoints surfaced on the daemon's
//! `web_ui.rs` router.
//!
//! Layout matches the existing `ws::fetch_list` pattern: a single async helper
//! per endpoint, taking the bearer token explicitly and returning `Result<Value,
//! String>` for the component layer to render directly. The token is read by
//! the panel components from the existing `AuthToken` context.
//!
//! The host build keeps the request-building logic compiled (path / params
//! shaping) so we can unit-test it without a wasm toolchain.

use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
use gloo_net::http::Request;

/// Endpoint path layout. Kept as a single constant so the host-side tests can
/// pin the URL shape without duplicating string literals.
pub mod paths {
    pub const SNAPSHOT_ROTATE_KEY: &str = "/api/v1/snapshot/{id}/rotate-key";
    pub const TOFU_EXPIRY: &str = "/api/v1/daemon/tofu-expiry";
    pub const PLUGIN_REVOKE_CLUSTER: &str = "/api/v1/plugin/key/revoke-cluster";
    pub const SANDBOX_AUTO_ENCRYPT: &str = "/api/v1/sandbox/auto-encrypt";
}

/// Substitute `{id}` in the snapshot rotate-key endpoint.
pub fn snapshot_rotate_key_url(snapshot_id: i64) -> String {
    paths::SNAPSHOT_ROTATE_KEY.replace("{id}", &snapshot_id.to_string())
}

/// Build the JSON body for the snapshot rotate-key endpoint. The daemon
/// translates this into a `Method::SnapshotKeyRotate` dispatch internally.
pub fn build_rotate_key_body(new_passphrase: &str) -> Value {
    json!({
        "new_passphrase": new_passphrase,
    })
}

/// Body for the TOFU expiry PUT endpoint. `None` means "clear the expiry".
pub fn build_tofu_expiry_body(max_age_secs: Option<u64>) -> Value {
    match max_age_secs {
        Some(secs) => json!({ "max_age_secs": secs }),
        None => json!({ "max_age_secs": null }),
    }
}

/// Body for the cluster-wide plugin key revocation endpoint.
pub fn build_revoke_cluster_body(
    publisher: &str,
    fingerprint: &str,
    reason: Option<&str>,
) -> Value {
    match reason {
        Some(r) => json!({
            "publisher": publisher,
            "fingerprint": fingerprint,
            "reason": r,
        }),
        None => json!({
            "publisher": publisher,
            "fingerprint": fingerprint,
        }),
    }
}

/// Body for the sandbox auto-encrypt PUT endpoint.
pub fn build_auto_encrypt_body(enabled: bool) -> Value {
    json!({ "enabled": enabled })
}

// ===========================================================================
// App-shell v5 — REST surface consumed by the dashboard / drawer / settings.
// URL builders are host-compiled + unit-tested; the wasm fetch wrappers below
// call the shared `send_get` / `send_post_json` helpers. Zero renumbering:
// these are all new axum routes (plus the one new `Method::SystemDf`).
// ===========================================================================

/// Stable path constants for the v5 endpoints. Pinned so a daemon-side route
/// rename is caught by `paths_v5_are_stable`.
pub mod paths_v5 {
    pub const SYSTEM_DF: &str = "/api/v1/system/df";
    pub const SYSTEM_INFO: &str = "/api/v1/system/info";
    pub const DOCTOR_RUN: &str = "/api/v1/doctor/run";
}

/// Percent-encode an RFC3339 timestamp for use as a query-string value. Mirrors
/// `encodeURIComponent` (alnum + `-_.~` intact) so `:` / `+` in the timestamp
/// survive proxies. Kept host-side so the shaping is unit-testable.
pub fn encode_query_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.as_bytes() {
        let c = *b;
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// `GET /api/v1/containers/:id/inspect` — full container inspect record.
pub fn container_inspect_url(id: &str) -> String {
    format!("/api/v1/containers/{}/inspect", encode_query_component(id))
}

/// `GET /api/v1/containers/:id/logs?tail=N&since=<rfc3339>`.
pub fn container_logs_url(id: &str, tail: Option<u32>, since: Option<&str>) -> String {
    let mut url = format!("/api/v1/containers/{}/logs", encode_query_component(id));
    let mut sep = '?';
    if let Some(t) = tail {
        url.push(sep);
        url.push_str(&format!("tail={t}"));
        sep = '&';
    }
    if let Some(s) = since {
        url.push(sep);
        url.push_str(&format!("since={}", encode_query_component(s)));
    }
    url
}

/// `GET /api/v1/metrics/:id` — latest single `MetricsSample` (or null).
pub fn metrics_latest_url(id: &str) -> String {
    format!("/api/v1/metrics/{}", encode_query_component(id))
}

/// `GET /api/v1/metrics/:id/history?since=<rfc3339>` — the ring buffer.
pub fn metrics_history_url(id: &str, since: Option<&str>) -> String {
    let base = format!("/api/v1/metrics/{}/history", encode_query_component(id));
    match since {
        Some(s) => format!("{base}?since={}", encode_query_component(s)),
        None => base,
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn fetch_container_inspect(id: &str, token: &str) -> Result<Value, String> {
    send_get(&container_inspect_url(id), token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn fetch_container_logs(
    id: &str,
    tail: Option<u32>,
    since: Option<&str>,
    token: &str,
) -> Result<Value, String> {
    send_get(&container_logs_url(id, tail, since), token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn fetch_metrics_latest(id: &str, token: &str) -> Result<Value, String> {
    send_get(&metrics_latest_url(id), token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn fetch_metrics_history(
    id: &str,
    since: Option<&str>,
    token: &str,
) -> Result<Value, String> {
    send_get(&metrics_history_url(id, since), token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn fetch_system_df(token: &str) -> Result<Value, String> {
    send_get(paths_v5::SYSTEM_DF, token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn fetch_system_info(token: &str) -> Result<Value, String> {
    send_get(paths_v5::SYSTEM_INFO, token).await
}

/// `POST /api/v1/doctor/run` — triggers the doctor sweep. Body is `{}`; the
/// daemon hard-codes `DoctorRunParams { json: true }`.
#[cfg(target_arch = "wasm32")]
pub async fn run_doctor(token: &str) -> Result<Value, String> {
    send_post_json(paths_v5::DOCTOR_RUN, json!({}), token).await
}

// ---------------------------------------------------------------------------
// wasm32 (browser) request helpers. Each builds the request via gloo-net and
// returns the decoded JSON body or a user-facing error string.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
async fn send_post_json(url: &str, body: Value, token: &str) -> Result<Value, String> {
    let resp = Request::post(url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| format!("request build error: {e:?}"))?
        .send()
        .await
        .map_err(|e| format!("fetch error: {e}"))?;
    decode_response(resp).await
}

#[cfg(target_arch = "wasm32")]
async fn send_put_json(url: &str, body: Value, token: &str) -> Result<Value, String> {
    let resp = Request::put(url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| format!("request build error: {e:?}"))?
        .send()
        .await
        .map_err(|e| format!("fetch error: {e}"))?;
    decode_response(resp).await
}

#[cfg(target_arch = "wasm32")]
async fn send_get(url: &str, token: &str) -> Result<Value, String> {
    let resp = Request::get(url)
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("fetch error: {e}"))?;
    decode_response(resp).await
}

#[cfg(target_arch = "wasm32")]
async fn decode_response(resp: gloo_net::http::Response) -> Result<Value, String> {
    if !resp.ok() {
        return Err(format!("http {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

#[cfg(target_arch = "wasm32")]
pub async fn rotate_snapshot_key(
    snapshot_id: i64,
    new_passphrase: &str,
    token: &str,
) -> Result<Value, String> {
    send_post_json(
        &snapshot_rotate_key_url(snapshot_id),
        build_rotate_key_body(new_passphrase),
        token,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn get_tofu_expiry(token: &str) -> Result<Value, String> {
    send_get(paths::TOFU_EXPIRY, token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn set_tofu_expiry(max_age_secs: Option<u64>, token: &str) -> Result<Value, String> {
    send_put_json(
        paths::TOFU_EXPIRY,
        build_tofu_expiry_body(max_age_secs),
        token,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn revoke_plugin_key_cluster_wide(
    publisher: &str,
    fingerprint: &str,
    reason: Option<&str>,
    token: &str,
) -> Result<Value, String> {
    send_post_json(
        paths::PLUGIN_REVOKE_CLUSTER,
        build_revoke_cluster_body(publisher, fingerprint, reason),
        token,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
pub async fn get_sandbox_auto_encrypt(token: &str) -> Result<Value, String> {
    send_get(paths::SANDBOX_AUTO_ENCRYPT, token).await
}

#[cfg(target_arch = "wasm32")]
pub async fn set_sandbox_auto_encrypt(enabled: bool, token: &str) -> Result<Value, String> {
    send_put_json(
        paths::SANDBOX_AUTO_ENCRYPT,
        build_auto_encrypt_body(enabled),
        token,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_rotate_key_url_interpolates_id() {
        assert_eq!(
            snapshot_rotate_key_url(42),
            "/api/v1/snapshot/42/rotate-key"
        );
        assert_eq!(snapshot_rotate_key_url(0), "/api/v1/snapshot/0/rotate-key");
    }

    #[test]
    fn build_rotate_key_body_carries_passphrase() {
        let body = build_rotate_key_body("hunter2");
        assert_eq!(
            body.get("new_passphrase").and_then(|v| v.as_str()),
            Some("hunter2")
        );
    }

    #[test]
    fn build_tofu_expiry_body_supports_some_and_none() {
        let some = build_tofu_expiry_body(Some(3_600));
        assert_eq!(
            some.get("max_age_secs").and_then(|v| v.as_u64()),
            Some(3_600)
        );
        let none = build_tofu_expiry_body(None);
        assert!(none.get("max_age_secs").is_some_and(|v| v.is_null()));
    }

    #[test]
    fn build_revoke_cluster_body_optional_reason() {
        let with = build_revoke_cluster_body("alice", "ff00", Some("compromised"));
        assert_eq!(
            with.get("publisher").and_then(|v| v.as_str()),
            Some("alice")
        );
        assert_eq!(
            with.get("reason").and_then(|v| v.as_str()),
            Some("compromised")
        );
        let without = build_revoke_cluster_body("bob", "0011", None);
        assert!(without.get("reason").is_none());
        assert_eq!(
            without.get("fingerprint").and_then(|v| v.as_str()),
            Some("0011")
        );
    }

    #[test]
    fn build_auto_encrypt_body_carries_flag() {
        assert_eq!(
            build_auto_encrypt_body(true)
                .get("enabled")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            build_auto_encrypt_body(false)
                .get("enabled")
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn paths_are_stable() {
        // Pin the path strings so daemon-side route changes are caught here.
        assert_eq!(
            paths::SNAPSHOT_ROTATE_KEY,
            "/api/v1/snapshot/{id}/rotate-key"
        );
        assert_eq!(paths::TOFU_EXPIRY, "/api/v1/daemon/tofu-expiry");
        assert_eq!(
            paths::PLUGIN_REVOKE_CLUSTER,
            "/api/v1/plugin/key/revoke-cluster"
        );
        assert_eq!(paths::SANDBOX_AUTO_ENCRYPT, "/api/v1/sandbox/auto-encrypt");
    }

    // ---- app-shell v5 URL builders -------------------------------------

    #[test]
    fn paths_v5_are_stable() {
        assert_eq!(paths_v5::SYSTEM_DF, "/api/v1/system/df");
        assert_eq!(paths_v5::SYSTEM_INFO, "/api/v1/system/info");
        assert_eq!(paths_v5::DOCTOR_RUN, "/api/v1/doctor/run");
    }

    #[test]
    fn container_inspect_url_is_nested_under_id() {
        assert_eq!(
            container_inspect_url("abc123"),
            "/api/v1/containers/abc123/inspect"
        );
    }

    #[test]
    fn container_logs_url_composes_query() {
        assert_eq!(
            container_logs_url("c1", None, None),
            "/api/v1/containers/c1/logs"
        );
        assert_eq!(
            container_logs_url("c1", Some(500), None),
            "/api/v1/containers/c1/logs?tail=500"
        );
        // `?` opens the query, `&` joins the second param; the `:` in the
        // timestamp is percent-encoded.
        assert_eq!(
            container_logs_url("c1", Some(200), Some("2026-07-21T12:00:00Z")),
            "/api/v1/containers/c1/logs?tail=200&since=2026-07-21T12%3A00%3A00Z"
        );
        assert_eq!(
            container_logs_url("c1", None, Some("2026-07-21T12:00:00Z")),
            "/api/v1/containers/c1/logs?since=2026-07-21T12%3A00%3A00Z"
        );
    }

    #[test]
    fn metrics_urls_shape() {
        assert_eq!(metrics_latest_url("m1"), "/api/v1/metrics/m1");
        assert_eq!(
            metrics_history_url("m1", None),
            "/api/v1/metrics/m1/history"
        );
        assert_eq!(
            metrics_history_url("m1", Some("2026-07-21T00:00:00+00:00")),
            "/api/v1/metrics/m1/history?since=2026-07-21T00%3A00%3A00%2B00%3A00"
        );
    }

    #[test]
    fn encode_query_component_leaves_unreserved() {
        assert_eq!(encode_query_component("abc-DEF_1.9~"), "abc-DEF_1.9~");
        assert_eq!(encode_query_component("a b"), "a%20b");
        assert_eq!(encode_query_component(":+"), "%3A%2B");
    }
}
