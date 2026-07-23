//! Dashboard — the at-a-glance home the SPA opens to (Docker Desktop parity).
//!
//! Spec v6 §4 "hero v2" layout, weighted top → bottom:
//!   * `.hero-row` — the visual anchor. A widest-column capacity donut (disk
//!     used/reclaimable/free from `system df`) at `--e-2` elevation, the two
//!     aggregate live charts (CPU% + Memory) at flat `--e-1`, and a quiet,
//!     borderless vertical count list — donut first, charts second, counts
//!     third, in that order of visual weight.
//!   * `.hero-secondary` — the recent-events feed beside a quick-actions card.
//!
//! Each fetch is independent so one failing endpoint never blanks the whole
//! page (preserved from the flat v1 layout).
//!
//! The aggregate CPU / memory ring buffers + running/total counts live in a
//! [`DashboardShared`] context that is *populated by the app-root poll loop*
//! (see `app.rs`) — the dashboard and the status footer both read it so we
//! never double-poll `GET /api/v1/metrics/:id`.

use std::collections::HashMap;

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::charts::{AreaChart, CapacityDonut};
use super::icons::Icon;
use super::live_events::LiveEvents;
use crate::app::{AuthToken, CreateIntent, CreateKind, Nav, Tab};
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

/// One `system df` category's `(size_bytes, reclaimable_bytes)`, defaulting
/// to zero when the category is absent (e.g. `build_cache` on older
/// daemons) — the donut degrades gracefully instead of erroring out.
fn df_category_bytes(df: &Value, key: &str) -> (u64, u64) {
    let cat = df.get(key);
    let size = cat
        .and_then(|c| c.get("size_bytes"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reclaimable = cat
        .and_then(|c| c.get("reclaimable_bytes"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (size, reclaimable)
}

/// Sum every `system df` category into `(used, reclaimable)` for the hero
/// donut. `used` is the *non-reclaimable* remainder (`size - reclaimable`),
/// so `used + reclaimable` always accounts for the whole tracked total —
/// there is no host-capacity field in `system df` to derive a real "free"
/// number from, so we never fabricate one (the donut's `free_bytes` stays 0
/// until such a field exists; see `CapacityDonut`'s doc comment).
fn df_used_reclaimable(res: &Option<Result<Value, String>>) -> (u64, u64) {
    let df = match res {
        Some(Ok(v)) => v,
        _ => return (0, 0),
    };
    let mut size_total = 0u64;
    let mut reclaim_total = 0u64;
    for key in ["images", "containers", "volumes", "build_cache"] {
        let (size, reclaim) = df_category_bytes(df, key);
        size_total = size_total.saturating_add(size);
        reclaim_total = reclaim_total.saturating_add(reclaim);
    }
    (size_total.saturating_sub(reclaim_total), reclaim_total)
}

/// `background:` inline style resolving a section's `--sec-<key>-fg` token —
/// used to tint a `.dot` with its resource's section hue (Spec v6 §4
/// hero-counts) without needing a new CSS class per section.
fn section_dot_style(key: &str) -> String {
    format!("background: var(--sec-{key}-fg)")
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let shared = use_context::<DashboardShared>().expect("DashboardShared provided by AppRoot");
    let nav = use_context::<Nav>().expect("Nav context provided by AppRoot");
    let create_intent = use_context::<CreateIntent>();

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

    // ---- capacity donut (hero-donut, widest column) ---------------------
    let used_bytes = Signal::derive(move || df_used_reclaimable(&df.get()).0);
    let reclaimable_bytes = Signal::derive(move || df_used_reclaimable(&df.get()).1);
    // No host-capacity field exists in `system df` yet — see `df_used_reclaimable`.
    let free_bytes = Signal::derive(|| 0u64);
    let manage_disk = Callback::new(move |()| nav.0.set(Tab::Disk));

    // ---- hero-counts tiles (quiet, third-priority column) ---------------
    let tile_containers = move || {
        let r = shared.running.get();
        let t = shared.total.get();
        view! {
            <div class="hero-counts__tile">
                <span class="stat-tile__label">
                    <span class="dot" style=section_dot_style("workloads")></span>
                    "Containers"
                </span>
                <span style="margin-left: auto; display: flex; align-items: center; gap: var(--sp-2)">
                    <span class="mono">{format!("{r}/{t}")}</span>
                    <span class="stat-tile__delta">"running / total"</span>
                </span>
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
            <div class="hero-counts__tile">
                <span class="stat-tile__label">
                    <span class="dot" style=section_dot_style("resources")></span>
                    "Images"
                </span>
                <span style="margin-left: auto; display: flex; align-items: center; gap: var(--sp-2)">
                    <span class="mono">{val}</span>
                    <span class="stat-tile__delta">{delta}</span>
                </span>
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
            <div class="hero-counts__tile">
                <span class="stat-tile__label">
                    <span class="dot" style=section_dot_style("resources")></span>
                    {label}
                </span>
                <span style="margin-left: auto; display: flex; align-items: center; gap: var(--sp-2)">
                    <span class="mono">{val}</span>
                    <span class="stat-tile__delta">{delta}</span>
                </span>
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
        // Daemon reachability is a *state*, not a resource section, so it
        // keeps the existing status-dot modifier rather than a section hue.
        let dot_cls = if ok {
            "dot dot--success"
        } else {
            "dot dot--danger"
        };
        view! {
            <div class="hero-counts__tile">
                <span class="stat-tile__label">
                    <span class=dot_cls></span>
                    "Daemon"
                </span>
                <span style="margin-left: auto; display: flex; align-items: center; gap: var(--sp-2)">
                    <span class="mono">{val}</span>
                    <span class="stat-tile__delta">{delta}</span>
                </span>
            </div>
        }
    };

    // ---- quick actions ----------------------------------------------------
    let new_container = move |_| {
        if let Some(intent) = create_intent {
            nav.0.set(Tab::Containers);
            intent.0.set(Some(CreateKind::Container));
        }
    };
    let run_doctor = move |_| nav.0.set(Tab::Settings);
    let open_terminal = move |_| nav.0.set(Tab::Containers);
    let on_refresh = move |_| refresh();

    view! {
        <div class="dashboard-panel section-scope--home">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="dashboard"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__title">"Dashboard"</div>
                        <div class="page-head__sub">"live overview of this linpodx daemon"</div>
                    </div>
                </div>
            </header>

            <div class="hero-row">
                <div class="hero-donut">
                    <CapacityDonut
                        used_bytes=used_bytes
                        reclaimable_bytes=reclaimable_bytes
                        free_bytes=free_bytes
                        on_manage=manage_disk
                    />
                </div>
                <div class="hero-charts">
                    <AreaChart
                        data=Signal::derive(move || shared.agg_cpu.get())
                        title="CPU %".to_string()
                        height=96.0
                        value_fmt=fmt_pct
                        zero_floor=true
                    />
                    <AreaChart
                        data=Signal::derive(move || shared.agg_mem.get())
                        title="Memory".to_string()
                        height=96.0
                        value_fmt=fmt_mem
                        zero_floor=true
                    />
                </div>
                <div class="hero-counts">
                    {tile_containers}
                    {tile_images}
                    {move || simple_tile("Volumes", volumes)}
                    {move || simple_tile("Networks", networks)}
                    {tile_daemon}
                </div>
            </div>

            <div class="hero-secondary">
                <LiveEvents/>
                <div class="quick-actions">
                    <div class="chart-card__title">"Quick actions"</div>
                    <div class="quick-actions__grid">
                        <button type="button" class="btn btn--sm btn--secondary" on:click=new_container>
                            "New container"
                        </button>
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
            </div>
        </div>
    }
}
