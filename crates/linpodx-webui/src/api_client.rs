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
}
