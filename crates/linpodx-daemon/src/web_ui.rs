//! Phase 8 — Browser-facing REST surface + embedded static UI.
//!
//! Mounted by `remote::build_router` under `/api/v1/*` (read-only JSON) and `/ui/*`
//! (static HTML/CSS/JS). Auth is the same bearer token used by the WebSocket
//! handshake; we just take it from the `Authorization: Bearer <token>` header here
//! so a vanilla `fetch()` from the browser can present it. Failure paths emit
//! `WebUiAccessDenied` audit entries; the first successful auth per peer emits
//! `WebUiSessionStarted`.
//!
//! The handlers are intentionally minimal: each one builds a synthetic `RpcRequest`
//! and re-uses the existing dispatcher so behavior matches the CLI/WS surface
//! exactly. There is no mutation surface on the Web UI yet — the CLI is the only
//! way to start/stop/remove anything.
//!
//! XSS posture: the UI never injects user-supplied strings via `innerHTML`; only
//! `textContent` is used. The server side returns `application/json`; static assets
//! are served with `mime_guess`-derived content types.
//!
//! NOTE: Phase 17 Stream E added four mutation endpoints (snapshot key rotate,
//! TOFU expiry get/set, plugin key cluster revoke, sandbox auto-encrypt
//! get/set). Each goes through the existing dispatcher so behaviour matches
//! the JSON-RPC and CLI surfaces; until Stage 2 fills in the underlying
//! dispatch arms the endpoints return a typed `not yet implemented` error.

use crate::dispatch::Dispatcher;
use crate::remote::constant_eq;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::ipc::{
    error_codes, responses, AuditQueryParams, ContainerIdParams, ContainerListParams,
    ContainerLogsParams, CreateOptions, DaemonPinClientTofuExpirySetParams, DoctorRunParams,
    ImageListParams, Method, MetricsHistoryParams, MetricsLatestParams,
    PluginKeyRevokePropagateParams, PodActionParams, PodCreateParams, PodRemoveParams,
    ResponsePayload, RpcError, RpcRequest, SandboxSnapshotAutoTriggerEnableParams,
    SessionListParams, SnapshotKeyRotateParams, SnapshotKeySource, SnapshotListParams,
};
use linpodx_common::types::ContainerId;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Shared state for the Web UI handlers + auth middleware.
#[derive(Clone)]
pub struct WebUiState {
    pub dispatcher: Arc<Dispatcher>,
    pub token: Arc<String>,
    pub audit: Arc<dyn AuditSink>,
    /// Tracks which `peer.ip()` strings we have already audited as "session
    /// started" so we only fire `WebUiSessionStarted` once per peer per process
    /// lifetime. The set is bounded by distinct caller IPs and reset on daemon
    /// restart — small, no eviction policy needed.
    pub seen_peers: Arc<Mutex<HashSet<String>>>,
}

/// Build the Web UI router. Returns a sub-router that the parent should mount
/// at the desired prefix (the parent typically `nest("/api/v1", ...)`s the API
/// half and adds a separate `/ui/*` route for the static assets).
pub fn router(
    dispatcher: Arc<Dispatcher>,
    token: Arc<String>,
    audit: Arc<dyn AuditSink>,
) -> Router {
    let state = WebUiState {
        dispatcher,
        token,
        audit,
        seen_peers: Arc::new(Mutex::new(HashSet::new())),
    };
    Router::new()
        .route("/containers", get(get_containers))
        .route("/containers/create", post(post_container_create))
        .route("/images", get(get_images))
        .route("/volumes", get(get_volumes))
        .route("/networks", get(get_networks))
        .route("/pods", get(get_pods))
        .route("/pods/create", post(post_pod_create))
        .route("/pods/:id/start", post(post_pod_start))
        .route("/pods/:id/stop", post(post_pod_stop))
        .route("/pods/:id/remove", post(post_pod_remove))
        .route("/snapshots", get(get_snapshots))
        .route("/sessions", get(get_sessions))
        .route("/sandbox/profiles", get(get_sandbox_profiles))
        .route("/audit", get(get_audit))
        .route("/metrics/:container_id", get(get_metrics))
        // Phase 25 — dashboard read surface. Inspect / logs / metrics history
        // reuse existing dispatch arms; system df/info + doctor add the last
        // pieces the SPA needs. All behind the same bearer middleware below.
        .route("/containers/:id/inspect", get(get_container_inspect))
        .route("/containers/:id/logs", get(get_container_logs))
        .route("/metrics/:container_id/history", get(get_metrics_history))
        .route("/system/df", get(get_system_df))
        .route("/system/info", get(get_system_info))
        .route("/doctor/run", post(post_doctor_run))
        // Phase 17 Stream E — mutating endpoints. They reuse the dispatcher so
        // the underlying Method::* arms (currently Stage 1 placeholders) take
        // over once Stream A/B/C teams wire them in.
        .route("/snapshot/:id/rotate-key", post(post_snapshot_rotate_key))
        .route(
            "/daemon/tofu-expiry",
            get(get_tofu_expiry).put(put_tofu_expiry),
        )
        .route(
            "/plugin/key/revoke-cluster",
            post(post_plugin_key_revoke_cluster),
        )
        .route(
            "/sandbox/auto-encrypt",
            get(get_sandbox_auto_encrypt).put(put_sandbox_auto_encrypt),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), bearer_auth))
        .with_state(state)
}

/// Build the static asset router — mount under `/ui` from the parent.
///
/// Phase 9 layout:
///
/// * `/ui/` (default) → leptos `index.html` shell, which loads
///   `linpodx_webui.{js,wasm}`. If the build script wrote stub bytes (i.e. the
///   `LINPODX_WASM=1` toolchain wasn't present), the routes transparently fall
///   back to the Phase 8 vanilla bundle and we log a one-time warning.
/// * `/ui/?legacy=1` → forces the Phase 8 vanilla `index.html`/`app.css`/`app.js`
///   bundle even when the WASM artifact is real. Useful for debugging.
/// * `/ui/app.css`, `/ui/app.js`, `/ui/index.html` → vanilla bundle assets.
/// * `/ui/linpodx_webui.wasm`, `/ui/linpodx_webui.js` → WASM bundle (or 404 if
///   we only have stub bytes).
pub fn static_router() -> Router {
    Router::new()
        .route("/", get(serve_root))
        .route("/index.html", get(serve_root_index))
        .route("/app.css", get(serve_legacy_asset))
        .route("/app.js", get(serve_legacy_asset))
        .route("/style.css", get(serve_legacy_asset))
        .route("/linpodx_webui.wasm", get(serve_wasm_blob))
        .route("/linpodx_webui.js", get(serve_wasm_js))
        // Phase 14: vendored xterm.js / addon-fit served from in-binary
        // bytes. Returns 404 in non-vendored builds so air-gapped operators
        // get a clear signal instead of a stub script.
        .route("/assets/xterm.js", get(serve_xterm_js))
        .route("/assets/xterm.css", get(serve_xterm_css))
        .route("/assets/addon-fit.js", get(serve_addon_fit_js))
        .route("/*path", get(serve_asset))
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn bearer_auth(
    State(state): State<WebUiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response<Body> {
    let presented = extract_bearer(&headers);
    let ok = presented
        .as_deref()
        .map(|t| constant_eq(t, state.token.as_str()))
        .unwrap_or(false);

    if !ok {
        state
            .audit
            .record(
                AuditSinkKind::WebUiAccessDenied,
                None,
                None,
                json!({
                    "peer": peer.to_string(),
                    "path": req.uri().path().to_string(),
                    "reason": if presented.is_some() { "token mismatch" } else { "missing bearer" },
                }),
            )
            .await;
        return unauthorized();
    }

    let peer_key = peer.ip().to_string();
    let mut seen = state.seen_peers.lock().await;
    if seen.insert(peer_key.clone()) {
        drop(seen);
        state
            .audit
            .record(
                AuditSinkKind::WebUiSessionStarted,
                None,
                None,
                json!({
                    "peer": peer.to_string(),
                    "path": req.uri().path().to_string(),
                }),
            )
            .await;
    }

    next.run(req).await
}

/// Pull the token out of `Authorization: Bearer <token>`. Returns `None` when the
/// header is missing or doesn't start with `Bearer `.
pub(crate) fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let trimmed = raw.trim();
    let (scheme, value) = trimmed.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = value.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn unauthorized() -> Response<Body> {
    let body = serde_json::to_string(&json!({
        "error": {
            "code": "unauthorized",
            "message": "missing or invalid bearer token",
        }
    }))
    .unwrap_or_else(|_| {
        String::from(r#"{"error":{"code":"unauthorized","message":"unauthorized"}}"#)
    });
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    resp
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn dispatch(state: &WebUiState, method: Method) -> Response<Body> {
    match dispatch_value(state, method).await {
        Ok(result) => Json(result).into_response(),
        Err(resp) => resp,
    }
}

/// Dispatch through the shared dispatcher and hand back the raw success
/// `result` JSON, or a ready-to-return 500 error envelope. Used by handlers
/// that post-process the payload (log tailing, `system/info` composition).
async fn dispatch_value(
    state: &WebUiState,
    method: Method,
) -> Result<serde_json::Value, Response<Body>> {
    let req = RpcRequest::new(0u32, method);
    let resp = state.dispatcher.dispatch(req).await;
    match resp.payload {
        ResponsePayload::Success { result } => Ok(result),
        ResponsePayload::Error { error } => Err(error_to_response(error)),
    }
}

/// Render a dispatch [`RpcError`] as the standard `{ "error": { code, message } }`
/// envelope with HTTP 500, matching the existing Web UI error contract.
fn error_to_response(error: RpcError) -> Response<Body> {
    warn!(code = error.code, message = %error.message, "web_ui dispatch error");
    let body = json!({ "error": { "code": error.code, "message": error.message } });
    let mut response = Json(body).into_response();
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

/// Build a 500 envelope for an internal (non-dispatch) failure — currently only
/// used when a well-formed dispatch success payload fails to re-decode.
fn internal_error(message: impl Into<String>) -> Response<Body> {
    let message = message.into();
    warn!(%message, "web_ui internal error");
    let body = json!({ "error": { "code": error_codes::INTERNAL, "message": message } });
    let mut response = Json(body).into_response();
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

async fn get_containers(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(
        &state,
        Method::ContainerList(ContainerListParams { all: true }),
    )
    .await
}

async fn post_container_create(
    State(state): State<WebUiState>,
    Json(options): Json<CreateOptions>,
) -> Response<Body> {
    dispatch(&state, Method::ContainerCreate(options)).await
}

async fn get_images(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::ImageList(ImageListParams::default())).await
}

async fn get_volumes(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::VolumeList).await
}

async fn get_networks(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::NetworkList).await
}

async fn get_pods(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::PodList).await
}

async fn post_pod_create(
    State(state): State<WebUiState>,
    Json(params): Json<PodCreateParams>,
) -> Response<Body> {
    dispatch(&state, Method::PodCreate(params)).await
}

async fn post_pod_start(State(state): State<WebUiState>, Path(id): Path<String>) -> Response<Body> {
    dispatch(&state, Method::PodStart(PodActionParams { id_or_name: id })).await
}

async fn post_pod_stop(State(state): State<WebUiState>, Path(id): Path<String>) -> Response<Body> {
    dispatch(&state, Method::PodStop(PodActionParams { id_or_name: id })).await
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct PodRemoveBody {
    #[serde(default)]
    pub force: bool,
}

async fn post_pod_remove(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
    Json(body): Json<PodRemoveBody>,
) -> Response<Body> {
    dispatch(
        &state,
        Method::PodRemove(PodRemoveParams {
            id_or_name: id,
            force: body.force,
        }),
    )
    .await
}

async fn get_snapshots(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::SnapshotList(SnapshotListParams::default())).await
}

async fn get_sessions(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::SessionList(SessionListParams::default())).await
}

async fn get_sandbox_profiles(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::SandboxProfileList).await
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct AuditQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

async fn get_audit(State(state): State<WebUiState>, Query(q): Query<AuditQuery>) -> Response<Body> {
    let params = AuditQueryParams {
        limit: q.limit,
        ..Default::default()
    };
    dispatch(&state, Method::AuditLogQuery(params)).await
}

async fn get_metrics(
    State(state): State<WebUiState>,
    Path(container_id): Path<String>,
) -> Response<Body> {
    dispatch(
        &state,
        Method::MetricsLatest(MetricsLatestParams { container_id }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Phase 25 — dashboard read surface (inspect / logs / history / df / info /
// doctor). Each reuses an existing dispatch arm except `system/df` (new
// `Method::SystemDf`) and `system/info` (composed in this layer).
// ---------------------------------------------------------------------------

/// `GET /api/v1/containers/:id/inspect` — reuses `Method::ContainerInspect`.
async fn get_container_inspect(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
) -> Response<Body> {
    dispatch(
        &state,
        Method::ContainerInspect(ContainerIdParams {
            id: ContainerId::new(id),
        }),
    )
    .await
}

/// Query for `GET /api/v1/containers/:id/logs`. `tail` bounds the returned
/// buffer to the last N `\n`-delimited lines of each stream (default 500);
/// `since` is passed through to `ContainerLogsParams.since`.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct LogsQuery {
    #[serde(default)]
    pub tail: Option<u32>,
    #[serde(default)]
    pub since: Option<String>,
}

/// `GET /api/v1/containers/:id/logs?tail=N&since=<rfc3339>` — reuses
/// `Method::ContainerLogs`. `tail` is applied here by truncating each stream to
/// its last N lines (the daemon has no source-side tail knob yet).
async fn get_container_logs(
    State(state): State<WebUiState>,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Response<Body> {
    let method = Method::ContainerLogs(ContainerLogsParams {
        id: ContainerId::new(id),
        since: q.since,
    });
    let value = match dispatch_value(&state, method).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let tail = q.tail.unwrap_or(500);
    Json(truncate_logs_value(value, tail)).into_response()
}

/// Truncate the `stdout`/`stderr` of a `LogsResponse` JSON value to the last
/// `tail` lines each. On any decode mismatch the value is returned unchanged so
/// the response shape is never corrupted.
pub(crate) fn truncate_logs_value(value: serde_json::Value, tail: u32) -> serde_json::Value {
    match serde_json::from_value::<responses::LogsResponse>(value.clone()) {
        Ok(logs) => {
            let truncated = responses::LogsResponse {
                stdout: tail_lines(&logs.stdout, tail),
                stderr: tail_lines(&logs.stderr, tail),
            };
            serde_json::to_value(truncated).unwrap_or(value)
        }
        Err(_) => value,
    }
}

/// Return the last `n` `\n`-delimited lines of `s`. When `s` already has `<= n`
/// lines it is returned verbatim (trailing newline preserved); when it is
/// trimmed the lines are re-joined with `\n`. `n == 0` yields an empty string.
pub(crate) fn tail_lines(s: &str, n: u32) -> String {
    if n == 0 {
        return String::new();
    }
    let n = n as usize;
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= n {
        return s.to_string();
    }
    lines[lines.len() - n..].join("\n")
}

/// Query for `GET /api/v1/metrics/:id/history`. `since` (RFC3339) bounds the
/// ring buffer; absent = full buffer.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct HistoryQuery {
    #[serde(default)]
    pub since: Option<String>,
}

/// `GET /api/v1/metrics/:id/history?since=<rfc3339>` — reuses
/// `Method::MetricsHistory`.
async fn get_metrics_history(
    State(state): State<WebUiState>,
    Path(container_id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Response<Body> {
    dispatch(
        &state,
        Method::MetricsHistory(MetricsHistoryParams {
            container_id,
            since: q.since,
        }),
    )
    .await
}

/// `GET /api/v1/system/df` — backed by the new `Method::SystemDf`.
async fn get_system_df(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::SystemDf).await
}

/// `GET /api/v1/system/info` — composite of `Method::Version` +
/// `Method::DaemonMgmtStatus`. Version is required; when only the status
/// dispatch fails the status-derived fields (`socket_path`, `uptime_secs`)
/// stay `null`. `web_listener_url` is not tracked by `WebUiState`, so it is
/// currently always `null` (contract-permitted).
async fn get_system_info(State(state): State<WebUiState>) -> Response<Body> {
    let version_val = match dispatch_value(&state, Method::Version).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let version: responses::VersionResponse = match serde_json::from_value(version_val) {
        Ok(v) => v,
        Err(e) => return internal_error(format!("system/info: decode version: {e}")),
    };

    // DaemonMgmtStatus is best-effort — its failure leaves the derived fields null.
    let (socket_path, uptime_secs) = match dispatch_value(&state, Method::DaemonMgmtStatus).await {
        Ok(v) => match serde_json::from_value::<responses::DaemonMgmtStatusResponse>(v) {
            Ok(status) => (
                status.socket_path.map(|p| p.display().to_string()),
                status.uptime_secs,
            ),
            Err(_) => (None, None),
        },
        Err(_) => (None, None),
    };

    let info = responses::SystemInfoResponse {
        linpodx_version: version.linpodx_version,
        ipc_version: version.ipc_version,
        podman_version: version.podman_version,
        socket_path,
        web_listener_url: None,
        uptime_secs,
    };
    Json(info).into_response()
}

/// `POST /api/v1/doctor/run` — reuses `Method::DoctorRun` with `json: true`.
/// Any request body is ignored.
async fn post_doctor_run(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::DoctorRun(DoctorRunParams { json: true })).await
}

// ---------------------------------------------------------------------------
// Phase 17 Stream E — mutation endpoints
// ---------------------------------------------------------------------------

/// JSON body for `POST /api/v1/snapshot/:id/rotate-key`. The Web UI sends a
/// new passphrase; this is currently the only key source the browser surfaces.
#[derive(Debug, Deserialize)]
pub(crate) struct RotateKeyBody {
    pub new_passphrase: String,
}

async fn post_snapshot_rotate_key(
    State(state): State<WebUiState>,
    Path(id): Path<i64>,
    Json(body): Json<RotateKeyBody>,
) -> Response<Body> {
    let params = SnapshotKeyRotateParams {
        snapshot_id: id,
        new_key: SnapshotKeySource::Passphrase {
            passphrase: body.new_passphrase,
        },
    };
    dispatch(&state, Method::SnapshotKeyRotate(params)).await
}

/// JSON body for `PUT /api/v1/daemon/tofu-expiry`. `max_age_secs = null`
/// clears the expiry (TOFU stays on until manually disabled).
#[derive(Debug, Deserialize)]
pub(crate) struct TofuExpiryBody {
    #[serde(default)]
    pub max_age_secs: Option<u64>,
}

async fn get_tofu_expiry(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::DaemonPinClientTofuExpiryStatus).await
}

async fn put_tofu_expiry(
    State(state): State<WebUiState>,
    Json(body): Json<TofuExpiryBody>,
) -> Response<Body> {
    let params = DaemonPinClientTofuExpirySetParams {
        max_age_secs: body.max_age_secs,
    };
    dispatch(&state, Method::DaemonPinClientTofuExpirySet(params)).await
}

/// JSON body for `POST /api/v1/plugin/key/revoke-cluster`.
#[derive(Debug, Deserialize)]
pub(crate) struct RevokeClusterBody {
    pub publisher: String,
    pub fingerprint: String,
    #[serde(default)]
    pub reason: Option<String>,
}

async fn post_plugin_key_revoke_cluster(
    State(state): State<WebUiState>,
    Json(body): Json<RevokeClusterBody>,
) -> Response<Body> {
    let params = PluginKeyRevokePropagateParams {
        publisher: body.publisher,
        fingerprint: body.fingerprint,
        reason: body.reason,
    };
    dispatch(&state, Method::PluginKeyRevokePropagate(params)).await
}

#[derive(Debug, Deserialize)]
pub(crate) struct AutoEncryptBody {
    pub enabled: bool,
}

async fn get_sandbox_auto_encrypt(State(state): State<WebUiState>) -> Response<Body> {
    dispatch(&state, Method::SandboxSnapshotAutoTriggerStatus).await
}

async fn put_sandbox_auto_encrypt(
    State(state): State<WebUiState>,
    Json(body): Json<AutoEncryptBody>,
) -> Response<Body> {
    let params = SandboxSnapshotAutoTriggerEnableParams {
        enabled: body.enabled,
    };
    dispatch(&state, Method::SandboxSnapshotAutoTriggerEnable(params)).await
}

// ---------------------------------------------------------------------------
// Static assets (baked into the binary)
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = include_str!("../web-ui/index.html");
const APP_CSS: &str = include_str!("../web-ui/app.css");
const APP_JS: &str = include_str!("../web-ui/app.js");
const WEBUI_INDEX_HTML: &str = include_str!("../../linpodx-webui/index.html");
/// Phase 10: dark gradient + accent #4a9eff stylesheet for the leptos SPA.
/// Served at `/ui/style.css`; referenced by `WEBUI_INDEX_HTML`.
const WEBUI_STYLE_CSS: &str = include_str!("../../linpodx-webui/src/style.css");
const WEBUI_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/linpodx_webui.wasm"));
const WEBUI_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/linpodx_webui.js"));

// Phase 14: vendored xterm.js + addon-fit. The daemon's build.rs writes either
// real downloaded bytes (when LINPODX_VENDOR_XTERM=1) or short text stubs
// (when unset). Serving them is gated on the `linpodx_xterm_vendored` cfg —
// stubs are baked in unconditionally so include_bytes! always succeeds.
const VENDORED_XTERM_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xterm.js"));
const VENDORED_XTERM_CSS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xterm.css"));
const VENDORED_ADDON_FIT_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/addon-fit.js"));

/// True when the daemon was built with `LINPODX_VENDOR_XTERM=1`. Surfaced as
/// a function so test code can assert against it without sprinkling cfg-attr
/// at every call site.
pub(crate) fn xterm_vendored() -> bool {
    cfg!(linpodx_xterm_vendored)
}

/// Whether the WASM artifact baked into the binary is a real wasm-bindgen
/// bundle or the placeholder stub written by `build.rs` when `LINPODX_WASM`
/// was unset / the toolchain was missing. We sniff for the textual
/// `// stub:` prefix the build script writes — real `.wasm` always starts
/// with the magic bytes `\0asm`.
pub(crate) fn wasm_is_stub() -> bool {
    WEBUI_WASM.starts_with(b"// stub")
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct LegacyQuery {
    #[serde(default)]
    pub legacy: Option<String>,
}

impl LegacyQuery {
    fn force_legacy(&self) -> bool {
        matches!(self.legacy.as_deref(), Some("1") | Some("true"))
    }
}

async fn serve_root(Query(q): Query<LegacyQuery>) -> Response<Body> {
    if q.force_legacy() || wasm_is_stub() {
        if !q.force_legacy() {
            debug!("serving legacy Web UI (wasm artifact is a stub)");
        }
        return serve_static_named("index.html");
    }
    let html = leptos_index_html();
    serve_inline("index.html", html.as_bytes())
}

/// Returns the leptos shell HTML, with xterm CDN URLs rewritten to local
/// `/ui/assets/...` paths when the daemon was built with
/// `LINPODX_VENDOR_XTERM=1`. The substitution happens once at first call and
/// is cached for the rest of the process.
pub(crate) fn leptos_index_html() -> &'static str {
    static CACHED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if !xterm_vendored() {
        return WEBUI_INDEX_HTML;
    }
    CACHED
        .get_or_init(|| rewrite_xterm_urls_to_local(WEBUI_INDEX_HTML))
        .as_str()
}

/// Rewrite the three jsDelivr URLs in the leptos shell to the embedded
/// daemon paths. Pure string substitution so it's trivially testable.
pub(crate) fn rewrite_xterm_urls_to_local(html: &str) -> String {
    html.replace(
        "https://cdn.jsdelivr.net/npm/@xterm/xterm@5/css/xterm.css",
        "/ui/assets/xterm.css",
    )
    .replace(
        "https://cdn.jsdelivr.net/npm/@xterm/xterm@5/lib/xterm.js",
        "/ui/assets/xterm.js",
    )
    .replace(
        "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10/lib/addon-fit.js",
        "/ui/assets/addon-fit.js",
    )
}

async fn serve_root_index(Query(q): Query<LegacyQuery>) -> Response<Body> {
    serve_root(Query(q)).await
}

async fn serve_legacy_asset(uri: axum::http::Uri) -> Response<Body> {
    let name = uri.path().trim_start_matches('/');
    serve_static_named(name)
}

async fn serve_wasm_blob() -> Response<Body> {
    if wasm_is_stub() {
        return not_found();
    }
    let mut resp = Response::new(Body::from(WEBUI_WASM));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/wasm".parse().expect("static mime parses"),
    );
    resp
}

async fn serve_wasm_js() -> Response<Body> {
    if wasm_is_stub() {
        return not_found();
    }
    serve_inline("linpodx_webui.js", WEBUI_JS.as_bytes())
}

// ---------------------------------------------------------------------------
// Phase 14: vendored xterm.js + addon-fit handlers
// ---------------------------------------------------------------------------

async fn serve_xterm_js() -> Response<Body> {
    serve_vendored_asset("xterm.js", VENDORED_XTERM_JS)
}

async fn serve_xterm_css() -> Response<Body> {
    serve_vendored_asset("xterm.css", VENDORED_XTERM_CSS)
}

async fn serve_addon_fit_js() -> Response<Body> {
    serve_vendored_asset("addon-fit.js", VENDORED_ADDON_FIT_JS)
}

/// Serve one of the embedded xterm assets. Returns 404 either when the daemon
/// was built without `LINPODX_VENDOR_XTERM=1` or when the embedded bytes are
/// the textual stub the build script writes by default. The stub sniff lets us
/// stay safe even if a future change re-enables include_bytes! in non-vendor
/// builds.
fn serve_vendored_asset(name: &str, body: &'static [u8]) -> Response<Body> {
    if !xterm_vendored() || asset_is_stub(body) {
        return not_found();
    }
    serve_inline(name, body)
}

/// Sniff for the textual `// stub:` prefix the build script writes when
/// LINPODX_VENDOR_XTERM is unset. Real downloaded assets never start with
/// these bytes (xterm.js is minified JS, xterm.css is minified CSS).
pub(crate) fn asset_is_stub(body: &[u8]) -> bool {
    body.starts_with(b"// stub")
}

fn serve_inline(name: &str, body: &'static [u8]) -> Response<Body> {
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    let content_type = mime.essence_str().to_string();
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type.parse().unwrap_or_else(|_| {
            "application/octet-stream"
                .parse()
                .expect("static fallback content-type parses")
        }),
    );
    debug!(asset = name, content_type, "served inline asset");
    resp
}

fn not_found() -> Response<Body> {
    let mut resp = Response::new(Body::from("not found"));
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp
}

async fn serve_asset(Path(path): Path<String>) -> Response<Body> {
    serve_static_named(&path)
}

pub(crate) fn serve_static_named(name: &str) -> Response<Body> {
    let trimmed = name.trim_start_matches('/');
    let effective = if trimmed.is_empty() {
        "index.html"
    } else {
        trimmed
    };

    let body: &'static str = match effective {
        "index.html" => INDEX_HTML,
        "app.css" => APP_CSS,
        "app.js" => APP_JS,
        "style.css" => WEBUI_STYLE_CSS,
        _ => {
            let mut resp = Response::new(Body::from("not found"));
            *resp.status_mut() = StatusCode::NOT_FOUND;
            return resp;
        }
    };

    let mime = mime_guess::from_path(effective).first_or_octet_stream();
    let content_type = mime.essence_str().to_string();

    let mut resp = Response::new(Body::from(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type.parse().unwrap_or_else(|_| {
            "application/octet-stream"
                .parse()
                .expect("static fallback content-type parses")
        }),
    );
    debug!(asset = effective, content_type, "served static asset");
    resp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn extract_bearer_parses_well_formed_header() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cret"),
        );
        assert_eq!(extract_bearer(&h), Some("s3cret".to_string()));
    }

    #[test]
    fn extract_bearer_is_scheme_case_insensitive() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer abc"),
        );
        assert_eq!(extract_bearer(&h), Some("abc".to_string()));
        let mut h2 = HeaderMap::new();
        h2.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("BEARER xyz"),
        );
        assert_eq!(extract_bearer(&h2), Some("xyz".to_string()));
    }

    #[test]
    fn extract_bearer_rejects_missing_or_wrong_scheme() {
        let h = HeaderMap::new();
        assert!(extract_bearer(&h).is_none());

        let mut h2 = HeaderMap::new();
        h2.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(extract_bearer(&h2).is_none());

        let mut h3 = HeaderMap::new();
        h3.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(extract_bearer(&h3).is_none());
    }

    #[test]
    fn constant_eq_used_for_token_compare() {
        // Sanity: the imported constant_eq still treats unequal tokens as a miss.
        // (Full algorithmic coverage lives in remote::tests.)
        assert!(constant_eq("token", "token"));
        assert!(!constant_eq("token", "Token"));
    }

    #[test]
    fn serve_static_named_returns_index_for_empty_path() {
        let resp = serve_static_named("");
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/html"), "got {ct:?}");
    }

    #[test]
    fn serve_static_named_returns_css_with_text_css_mime() {
        let resp = serve_static_named("app.css");
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/css"), "got {ct:?}");
    }

    #[test]
    fn serve_static_named_returns_js_with_javascript_mime() {
        let resp = serve_static_named("app.js");
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // mime_guess emits "application/javascript" for .js; some platforms may
        // map it to "text/javascript". Accept either to stay portable.
        assert!(
            ct.contains("javascript"),
            "expected a javascript mime, got {ct:?}"
        );
    }

    #[test]
    fn serve_static_named_404s_for_unknown_asset() {
        let resp = serve_static_named("does-not-exist.png");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn serve_static_named_strips_leading_slash() {
        let resp = serve_static_named("/app.css");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn unauthorized_response_has_json_content_type() {
        let resp = unauthorized();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn audit_query_default_limit_is_none() {
        let q: AuditQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(q.limit.is_none());
    }

    #[test]
    fn audit_query_parses_limit() {
        let q: AuditQuery = serde_json::from_value(serde_json::json!({"limit": 50})).unwrap();
        assert_eq!(q.limit, Some(50));
    }

    // ---- Phase 25: dashboard read surface helpers ----

    #[test]
    fn tail_lines_returns_verbatim_when_under_limit() {
        let s = "a\nb\nc\n";
        assert_eq!(tail_lines(s, 500), s);
        assert_eq!(tail_lines("only-line", 5), "only-line");
    }

    #[test]
    fn tail_lines_trims_to_last_n() {
        let s = "l1\nl2\nl3\nl4\nl5";
        assert_eq!(tail_lines(s, 2), "l4\nl5");
        assert_eq!(tail_lines(s, 3), "l3\nl4\nl5");
    }

    #[test]
    fn tail_lines_zero_yields_empty() {
        assert_eq!(tail_lines("a\nb\nc", 0), "");
    }

    #[test]
    fn tail_lines_empty_input_is_empty() {
        assert_eq!(tail_lines("", 10), "");
    }

    #[test]
    fn truncate_logs_value_trims_both_streams() {
        let v = serde_json::json!({
            "stdout": "o1\no2\no3\no4",
            "stderr": "e1\ne2\ne3",
        });
        let out = truncate_logs_value(v, 2);
        assert_eq!(out["stdout"], "o3\no4");
        assert_eq!(out["stderr"], "e2\ne3");
    }

    #[test]
    fn truncate_logs_value_passes_through_unexpected_shape() {
        // A payload that is not a LogsResponse must be returned unchanged.
        let v = serde_json::json!({ "something": "else" });
        let out = truncate_logs_value(v.clone(), 10);
        assert_eq!(out, v);
    }

    #[test]
    fn logs_query_defaults_are_none() {
        let q: LogsQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(q.tail.is_none());
        assert!(q.since.is_none());
    }

    #[test]
    fn logs_query_parses_tail_and_since() {
        let q: LogsQuery = serde_json::from_value(
            serde_json::json!({"tail": 100, "since": "2026-07-21T12:00:00Z"}),
        )
        .unwrap();
        assert_eq!(q.tail, Some(100));
        assert_eq!(q.since.as_deref(), Some("2026-07-21T12:00:00Z"));
    }

    #[test]
    fn history_query_parses_since() {
        let q: HistoryQuery =
            serde_json::from_value(serde_json::json!({"since": "2026-07-21T12:00:00Z"})).unwrap();
        assert_eq!(q.since.as_deref(), Some("2026-07-21T12:00:00Z"));
        let empty: HistoryQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.since.is_none());
    }

    #[test]
    fn error_to_response_is_500_json_envelope() {
        let resp = error_to_response(RpcError {
            code: error_codes::NOT_FOUND,
            message: "no such container".into(),
            data: None,
        });
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("application/json"), "got {ct:?}");
    }

    #[test]
    fn system_info_response_serializes_all_keys() {
        // The frontend binds to every key including the nullable ones.
        let info = responses::SystemInfoResponse {
            linpodx_version: "0.1.5".into(),
            ipc_version: 1,
            podman_version: "5.8.1".into(),
            socket_path: Some("/run/user/1000/linpodx.sock".into()),
            web_listener_url: None,
            uptime_secs: Some(3625),
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["linpodx_version"], "0.1.5");
        assert_eq!(v["ipc_version"], 1);
        assert_eq!(v["socket_path"], "/run/user/1000/linpodx.sock");
        assert!(v["web_listener_url"].is_null());
        assert_eq!(v["uptime_secs"], 3625);
    }

    #[test]
    fn static_assets_are_non_empty() {
        // Guarantees the include_str! macros caught real files.
        assert!(!std::hint::black_box(INDEX_HTML).is_empty());
        assert!(INDEX_HTML.contains("linpodx"));
        assert!(!std::hint::black_box(APP_CSS).is_empty());
        assert!(!std::hint::black_box(APP_JS).is_empty());
        // Defense-in-depth XSS check: the JS shouldn't write into innerHTML.
        // We look for the assignment sink rather than the bare identifier so a
        // comment like "no innerHTML use" wouldn't trip the guard.
        assert!(
            !APP_JS.contains(".innerHTML"),
            "app.js must not assign to .innerHTML — textContent only"
        );
    }

    #[test]
    fn legacy_query_parses_truthy_values() {
        let q1: LegacyQuery = serde_json::from_value(serde_json::json!({"legacy": "1"})).unwrap();
        assert!(q1.force_legacy());
        let q2: LegacyQuery =
            serde_json::from_value(serde_json::json!({"legacy": "true"})).unwrap();
        assert!(q2.force_legacy());
        let q3: LegacyQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!q3.force_legacy());
        let q4: LegacyQuery = serde_json::from_value(serde_json::json!({"legacy": "0"})).unwrap();
        assert!(!q4.force_legacy());
    }

    #[test]
    fn webui_index_html_is_baked_in() {
        // The leptos shell must be embedded so `serve_root` can hand it back
        // without touching the filesystem.
        assert!(WEBUI_INDEX_HTML.contains("linpodx_webui"));
        assert!(WEBUI_INDEX_HTML.contains("/ui/linpodx_webui.wasm"));
    }

    #[test]
    fn wasm_stub_is_detected_when_toolchain_absent() {
        // Without LINPODX_WASM the build script writes a textual stub. CI
        // should run with the var unset, so this test pins the fallback path.
        // If a future CI run sets LINPODX_WASM, real bytes will start with
        // the wasm magic `\0asm`, so we just assert the sniff is consistent.
        let stub = wasm_is_stub();
        if stub {
            assert!(WEBUI_WASM.starts_with(b"// stub"));
        } else {
            assert!(
                WEBUI_WASM.starts_with(b"\0asm"),
                "non-stub wasm must start with the wasm magic"
            );
        }
    }

    #[tokio::test]
    async fn serve_wasm_blob_404s_when_stub() {
        if !wasm_is_stub() {
            // Real bundle present — nothing to assert here.
            return;
        }
        let resp = serve_wasm_blob().await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_root_returns_legacy_when_query_set() {
        let q = LegacyQuery {
            legacy: Some("1".into()),
        };
        let resp = serve_root(Query(q)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/html"), "got {ct:?}");
        // Pull the body and confirm it's the vanilla bundle (it references app.js).
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            body.contains("app.js"),
            "legacy bundle should reference vanilla app.js"
        );
    }

    #[tokio::test]
    async fn serve_root_returns_leptos_shell_when_real_wasm_present() {
        if wasm_is_stub() {
            // Without the wasm pipeline, root falls back to the vanilla shell —
            // covered by `serve_root_returns_legacy_when_query_set` above.
            return;
        }
        let q = LegacyQuery::default();
        let resp = serve_root(Query(q)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            body.contains("linpodx_webui.js"),
            "leptos shell should reference the wasm-bindgen js shim"
        );
    }

    // ---- Phase 14: vendored xterm.js infra ----

    #[test]
    fn vendored_xterm_assets_are_embedded() {
        // The build script writes either real bytes or a textual stub; in both
        // cases include_bytes! must succeed and the slice must be non-empty.
        assert!(
            !std::hint::black_box(VENDORED_XTERM_JS).is_empty(),
            "xterm.js include_bytes! produced an empty slice"
        );
        assert!(
            !std::hint::black_box(VENDORED_XTERM_CSS).is_empty(),
            "xterm.css include_bytes! produced an empty slice"
        );
        assert!(
            !std::hint::black_box(VENDORED_ADDON_FIT_JS).is_empty(),
            "addon-fit.js include_bytes! produced an empty slice"
        );
    }

    #[test]
    fn asset_is_stub_detects_build_script_prefix() {
        assert!(asset_is_stub(b"// stub: xterm asset not vendored\n"));
        assert!(asset_is_stub(b"// stub"));
        assert!(!asset_is_stub(b"!function(){var t=...}"));
        assert!(!asset_is_stub(b".terminal { color: white; }"));
        assert!(!asset_is_stub(b""));
    }

    #[test]
    fn asset_is_stub_recognises_default_build_output() {
        // Without LINPODX_VENDOR_XTERM, the build script writes the textual
        // stub. Pin that as a regression guard so future changes notice if
        // the stub format diverges from the sniff.
        if !xterm_vendored() {
            assert!(
                asset_is_stub(VENDORED_XTERM_JS),
                "default build should embed the textual stub for xterm.js"
            );
        }
    }

    #[test]
    fn rewrite_xterm_urls_swaps_all_three_assets() {
        let original = r#"
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5/css/xterm.css">
            <script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5/lib/xterm.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10/lib/addon-fit.js"></script>
        "#;
        let rewritten = rewrite_xterm_urls_to_local(original);
        assert!(rewritten.contains("/ui/assets/xterm.css"));
        assert!(rewritten.contains("/ui/assets/xterm.js"));
        assert!(rewritten.contains("/ui/assets/addon-fit.js"));
        assert!(
            !rewritten.contains("cdn.jsdelivr.net"),
            "no jsDelivr URL should remain after rewrite: {rewritten}"
        );
    }

    #[test]
    fn rewrite_xterm_urls_is_idempotent_on_local_paths() {
        let already_local = r#"<script src="/ui/assets/xterm.js"></script>"#;
        let rewritten = rewrite_xterm_urls_to_local(already_local);
        assert_eq!(
            rewritten, already_local,
            "rewrite must not double-mangle already-local URLs"
        );
    }

    #[test]
    fn webui_index_html_references_xterm_in_one_form_or_another() {
        // Either the CDN URL (default build) or the local path (vendored)
        // must appear in the leptos shell so the Logs/Exec modals can load.
        let html = leptos_index_html();
        let has_cdn = html.contains("cdn.jsdelivr.net/npm/@xterm/xterm@5");
        let has_local = html.contains("/ui/assets/xterm.js");
        assert!(
            has_cdn || has_local,
            "leptos shell must reference xterm.js via CDN or local path"
        );
        if xterm_vendored() {
            assert!(
                has_local && !has_cdn,
                "vendored build should serve xterm locally, not from the CDN"
            );
        } else {
            assert!(
                has_cdn && !has_local,
                "default build should still load xterm from jsDelivr"
            );
        }
    }

    #[tokio::test]
    async fn serve_xterm_js_404s_when_not_vendored_or_stub() {
        let resp = serve_xterm_js().await;
        if !xterm_vendored() || asset_is_stub(VENDORED_XTERM_JS) {
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "non-vendored / stub builds must 404 the local xterm.js path"
            );
        } else {
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn serve_xterm_css_404s_when_not_vendored_or_stub() {
        let resp = serve_xterm_css().await;
        if !xterm_vendored() || asset_is_stub(VENDORED_XTERM_CSS) {
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        } else {
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn serve_addon_fit_js_404s_when_not_vendored_or_stub() {
        let resp = serve_addon_fit_js().await;
        if !xterm_vendored() || asset_is_stub(VENDORED_ADDON_FIT_JS) {
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        } else {
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
}
