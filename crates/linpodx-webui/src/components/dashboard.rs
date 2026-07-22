//! Dashboard — the at-a-glance home the SPA opens to (Docker Desktop parity).
//!
//! Layout (top → bottom): a stat-tile row, two aggregate live charts (CPU% +
//! Memory), a recent-events feed and a quick-actions row. Each fetch is
//! independent so one failing endpoint never blanks the whole page.
//!
//! The aggregate CPU / memory ring buffers + running/total counts live in a
//! [`DashboardShared`] context that is *populated by the app-root poll loop*
//! (see `app.rs`) — the dashboard and the status footer both read it so we
//! never double-poll `GET /api/v1/metrics/:id`.

use std::collections::HashMap;

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::charts::AreaChart;
use super::live_events::LiveEvents;
use crate::app::{AuthToken, Nav, Tab};
use crate::helpers::format_bytes;
use crate::ws::fetch_list;

/// One container's latest metrics sample, as kept in
/// [`DashboardShared::latest_metrics`]. `cpu_pct` is a fraction (matches the
/// daemon's `MetricsSample.cpu_pct` wire units — multiply by 100 to display).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContainerLiveSample {
    pub cpu_pct: f64,
    pub mem_bytes: f64,
}

/// Aggregate live-metrics ring buffers + coarse daemon status, shared between
/// the dashboard body and the status footer via context. All fields are `Copy`
/// signals so the struct itself is `Copy`.
#[derive(Clone, Copy)]
pub struct DashboardShared {
    /// (epoch_secs, aggregate cpu percent) ring, capped at 60 samples.
    pub agg_cpu: RwSignal<Vec<(f64, f64)>>,
    /// (epoch_secs, aggregate memory bytes) ring, capped at 60 samples.
    pub agg_mem: RwSignal<Vec<(f64, f64)>>,
    pub running: RwSignal<u32>,
    pub total: RwSignal<u32>,
    /// True after the last metrics-poll fetch succeeded; false on 401 / error.
    pub connected: RwSignal<bool>,
    pub version: RwSignal<String>,
    /// Per-container latest metrics sample, keyed by container id. Rebuilt
    /// wholesale on every poll tick (rather than merged) so a container that
    /// stops or disappears drops out of the map instead of showing a stale
    /// reading — the Containers table CPU/Mem columns and any other live-cell
    /// consumer read this directly instead of re-fetching per row.
    pub latest_metrics: RwSignal<HashMap<String, ContainerLiveSample>>,
}

impl DashboardShared {
    pub fn new() -> Self {
        Self {
            agg_cpu: RwSignal::new(Vec::new()),
            agg_mem: RwSignal::new(Vec::new()),
            running: RwSignal::new(0),
            total: RwSignal::new(0),
            connected: RwSignal::new(false),
            version: RwSignal::new(String::new()),
            latest_metrics: RwSignal::new(HashMap::new()),
        }
    }
}

impl Default for DashboardShared {
    fn default() -> Self {
        Self::new()
    }
}

/// Percent formatter for the CPU chart's big number. One decimal, matching
/// every other percent rendering in the app (containers table, Stats tab).
fn fmt_pct(v: f64) -> String {
    format!("{v:.1}%")
}

/// Byte formatter for the memory chart's big number.
fn fmt_mem(v: f64) -> String {
    format_bytes(v.max(0.0) as u64)
}

/// Count the elements of a JSON array response, or `None` when the fetch is
/// still pending / errored.
fn arr_len(res: &Option<Result<Value, String>>) -> Option<usize> {
    match res {
        Some(Ok(Value::Array(a))) => Some(a.len()),
        _ => None,
    }
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let shared = use_context::<DashboardShared>().expect("DashboardShared provided by AppRoot");
    let nav = use_context::<Nav>().expect("Nav context provided by AppRoot");

    // Per-tile fetch state. `None` = loading; `Some(Ok)` / `Some(Err)`.
    let images = RwSignal::new(None::<Result<Value, String>>);
    let volumes = RwSignal::new(None::<Result<Value, String>>);
    let networks = RwSignal::new(None::<Result<Value, String>>);
    let df = RwSignal::new(None::<Result<Value, String>>);
    let info = RwSignal::new(None::<Result<Value, String>>);

    // One-shot fetch driver, reusable by the "Refresh" quick action.
    let refresh = move || {
        let token = auth.0.get_untracked().unwrap_or_default();
        images.set(None);
        volumes.set(None);
        networks.set(None);
        df.set(None);
        info.set(None);
        spawn_local(async move {
            images.set(Some(fetch_list("images", &token).await));
            volumes.set(Some(fetch_list("volumes", &token).await));
            networks.set(Some(fetch_list("networks", &token).await));
            df.set(Some(crate::api_client::fetch_system_df(&token).await));
            info.set(Some(crate::api_client::fetch_system_info(&token).await));
        });
    };
    refresh();

    // ---- stat tiles ----------------------------------------------------
    let tile_containers = move || {
        let r = shared.running.get();
        let t = shared.total.get();
        view! {
            <div class="stat-tile">
                <span class="stat-tile__label">"Containers"</span>
                <span class="stat-tile__value mono">{format!("{r}/{t}")}</span>
                <span class="stat-tile__delta">"running / total"</span>
            </div>
        }
    };

    let tile_images = move || {
        let count = arr_len(&images.get());
        let size = df.get().and_then(|r| {
            r.ok()
                .and_then(|v| v.get("images").and_then(|i| i.get("size_bytes")).cloned())
                .and_then(|s| s.as_u64())
        });
        let (val, delta) = match (count, images.get()) {
            (Some(c), _) => (
                c.to_string(),
                match size {
                    Some(b) => format!("· {}", format_bytes(b)),
                    None => "images".to_string(),
                },
            ),
            (None, Some(Err(e))) => ("—".to_string(), e),
            _ => ("…".to_string(), "loading".to_string()),
        };
        view! {
            <div class="stat-tile">
                <span class="stat-tile__label">"Images"</span>
                <span class="stat-tile__value mono">{val}</span>
                <span class="stat-tile__delta">{delta}</span>
            </div>
        }
    };

    let simple_tile = move |label: &'static str, res: RwSignal<Option<Result<Value, String>>>| {
        let (val, delta) = match res.get() {
            Some(Ok(Value::Array(a))) => (a.len().to_string(), String::from("total")),
            Some(Ok(_)) => ("0".to_string(), String::from("total")),
            Some(Err(e)) => ("—".to_string(), e),
            None => ("…".to_string(), "loading".to_string()),
        };
        view! {
            <div class="stat-tile">
                <span class="stat-tile__label">{label}</span>
                <span class="stat-tile__value mono">{val}</span>
                <span class="stat-tile__delta">{delta}</span>
            </div>
        }
    };

    let tile_daemon = move || {
        let (val, delta, ok) = match info.get() {
            Some(Ok(v)) => {
                let lp = v
                    .get("linpodx_version")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?")
                    .to_string();
                let pod = v
                    .get("podman_version")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?")
                    .to_string();
                (format!("v{lp}"), format!("podman {pod}"), true)
            }
            Some(Err(e)) => ("—".to_string(), e, false),
            None => ("…".to_string(), "loading".to_string(), false),
        };
        let dot_cls = if ok {
            "dot dot--success"
        } else {
            "dot dot--danger"
        };
        view! {
            <div class="stat-tile">
                <span class="stat-tile__label">
                    <span class=dot_cls></span>" Daemon"
                </span>
                <span class="stat-tile__value mono">{val}</span>
                <span class="stat-tile__delta">{delta}</span>
            </div>
        }
    };

    // ---- quick actions -------------------------------------------------
    let run_doctor = move |_| nav.0.set(Tab::Settings);
    let open_terminal = move |_| nav.0.set(Tab::Containers);
    let on_refresh = move |_| refresh();

    view! {
        <div class="dashboard-panel">
            <div class="page-header">
                <div class="page-header__titles">
                    <div class="page-title">"Dashboard"</div>
                    <div class="page-subtitle">"live overview of this linpodx daemon"</div>
                </div>
                <div class="page-actions">
                    <button type="button" class="btn btn--sm btn--secondary" on:click=run_doctor>
                        "Run doctor"
                    </button>
                    <button type="button" class="btn btn--sm btn--secondary" on:click=open_terminal>
                        "Open terminal"
                    </button>
                    <button type="button" class="btn btn--sm btn--secondary" on:click=on_refresh>
                        "Refresh"
                    </button>
                </div>
            </div>

            <div class="stat-tile-grid">
                {tile_containers}
                {tile_images}
                {move || simple_tile("Volumes", volumes)}
                {move || simple_tile("Networks", networks)}
                {tile_daemon}
            </div>

            <div class="chart-row">
                <AreaChart
                    data=Signal::derive(move || shared.agg_cpu.get())
                    title="CPU %".to_string()
                    height=130.0
                    value_fmt=fmt_pct
                    zero_floor=true
                />
                <AreaChart
                    data=Signal::derive(move || shared.agg_mem.get())
                    title="Memory".to_string()
                    height=130.0
                    value_fmt=fmt_mem
                    zero_floor=true
                />
            </div>

            <LiveEvents/>
        </div>
    }
}
