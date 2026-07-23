//! Dashboard — the at-a-glance home the SPA opens to (Docker Desktop parity).
//!
//! Layout, weighted top → bottom:
//!   * `.hero-row` — the visual anchor. A widest-column capacity donut (disk
//!     used/reclaimable from `system df`) at `--e-2` elevation, the two
//!     aggregate live charts (CPU% + Memory) at flat `--e-1`, and a column of
//!     clickable resource count-cards that navigate to their tab — donut first,
//!     charts second, count-cards third, in that order of visual weight.
//!   * `.hero-secondary` — the recent-events feed beside a quick-actions +
//!     "top consumers" card.
//!
//! The dashboard renders WITHOUT the shared `.page-head` block (the topbar
//! crumb already reads "Dashboard", so a second page-head title is a duplicate);
//! every other tab keeps its page-head.
//!
//! Each fetch is independent so one failing endpoint never blanks the whole
//! page. On mount the dashboard also *backfills* the aggregate CPU / memory
//! rings (and per-container CPU sparkline rings) from each running container's
//! `GET /api/v1/metrics/:id/history` so the area charts show a real shape
//! immediately instead of a lone hairline that fills 1 point / 2 s.
//!
//! The aggregate CPU / memory ring buffers + running/total counts live in a
//! [`DashboardShared`] context that is *populated by the app-root poll loop*
//! (see `app.rs`) — the dashboard and the status footer both read it so we
//! never double-poll `GET /api/v1/metrics/:id`.

use std::collections::{BTreeMap, HashMap};

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::charts::{AreaChart, CapacityDonut, Sparkline};
use super::icons::Icon;
use super::live_events::LiveEvents;
use crate::app::{AuthToken, CreateIntent, CreateKind, DrawerState, Nav, Tab};
use crate::helpers::{container_display_name, format_bytes, parse_rfc3339_epoch, short_id};
use crate::ws::fetch_list;

/// Ring-buffer cap shared by the aggregate rings (app-root uses the same 60) and
/// the per-container sparkline rings the dashboard maintains for "top consumers".
const RING_CAP: usize = 60;

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
/// so `used + reclaimable` always accounts for the whole tracked total.
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

/// A container is "running" if its status string reads like podman's `Up …` /
/// `running`. Mirrors `app.rs`'s private `is_running` — the metrics history
/// endpoint only has samples for running containers.
fn is_running_status(status: &str) -> bool {
    let s = status.to_lowercase();
    s.contains("up") || s.contains("running")
}

/// Running container ids from a `containers?all=true` list response.
fn running_ids(list: &Result<Value, String>) -> Vec<String> {
    let arr = match list {
        Ok(Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    arr.iter()
        .filter(|c| {
            c.get("status")
                .and_then(Value::as_str)
                .map(is_running_status)
                .unwrap_or(false)
        })
        .filter_map(|c| c.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// Build an `id → display-name` map from a `containers?all=true` list response
/// so the "top consumers" table can label rows the live-metrics map only keys
/// by id.
fn id_name_map(res: &Option<Result<Value, String>>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(Ok(Value::Array(arr))) = res {
        for c in arr {
            let id = c.get("id").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let names: Vec<String> = c
                .get("names")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            map.insert(id.to_string(), container_display_name(&names, id));
        }
    }
    map
}

/// Cap a chronological ring to its newest [`RING_CAP`] samples in place.
fn cap_ring(ring: &mut Vec<(f64, f64)>) {
    let n = ring.len();
    if n > RING_CAP {
        ring.drain(0..n - RING_CAP);
    }
}

/// Merge backfilled (historical) points into an aggregate ring signal, keeping
/// only points strictly *older* than the earliest sample already present so a
/// live sample the poll loop pushed between mount and backfill-resolution is
/// never clobbered or duplicated. Both inputs are ascending by timestamp.
fn merge_older(sig: RwSignal<Vec<(f64, f64)>>, backfill: Vec<(f64, f64)>) {
    if backfill.is_empty() {
        return;
    }
    sig.update(|cur| {
        let earliest = cur.iter().map(|&(t, _)| t).fold(f64::INFINITY, f64::min);
        let mut merged: Vec<(f64, f64)> = backfill
            .into_iter()
            .filter(|&(t, _)| t < earliest)
            .collect();
        merged.extend(cur.iter().copied());
        cap_ring(&mut merged);
        *cur = merged;
    });
}

/// A single clickable resource count-card in the hero-counts column. Reads the
/// [`Nav`] context so a click routes to the owning tab. `sec` is the owning
/// section's stable key (`workloads` / `resources` / `system`) whose accent
/// trio tints the icon disc.
fn count_card(
    icon: &'static str,
    sec: &'static str,
    label: &'static str,
    target: Tab,
    value: Signal<String>,
    sub: Signal<String>,
) -> impl IntoView {
    let nav = use_context::<Nav>().expect("Nav context provided by AppRoot");
    view! {
        <button
            type="button"
            class="hero-counts__card"
            style=format!("--card-fg: var(--sec-{sec}-fg); --card-disc: var(--sec-{sec}-disc)")
            on:click=move |_| nav.0.set(target)
        >
            <span class="hero-counts__disc"><Icon name=icon/></span>
            <span class="hero-counts__body">
                <span class="hero-counts__label">{label}</span>
                <span class="hero-counts__count mono">{move || value.get()}</span>
                <span class="hero-counts__sub">{move || sub.get()}</span>
            </span>
        </button>
    }
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let shared = use_context::<DashboardShared>().expect("DashboardShared provided by AppRoot");
    let nav = use_context::<Nav>().expect("Nav context provided by AppRoot");
    let drawer = use_context::<DrawerState>().expect("DrawerState provided by AppRoot");
    let create_intent = use_context::<CreateIntent>();

    // Per-tile fetch state. `None` = loading; `Some(Ok)` / `Some(Err)`.
    let images = RwSignal::new(None::<Result<Value, String>>);
    let volumes = RwSignal::new(None::<Result<Value, String>>);
    let networks = RwSignal::new(None::<Result<Value, String>>);
    let df = RwSignal::new(None::<Result<Value, String>>);
    let info = RwSignal::new(None::<Result<Value, String>>);
    // Container list (id → name) for the "top consumers" table + running-set
    // seed for the metrics backfill. Fetched once on mount by the backfill.
    let containers = RwSignal::new(None::<Result<Value, String>>);
    // Per-container CPU% sparkline rings for "top consumers", seeded from
    // metrics history on mount and appended from `latest_metrics` each tick.
    let cpu_rings = RwSignal::new(HashMap::<String, Vec<(f64, f64)>>::new());

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

    // Backfill the aggregate CPU/mem rings + per-container sparkline rings from
    // each running container's metrics history, so the charts are shaped on the
    // very first paint instead of drawing a lone hairline for the first minute.
    if let Some(tok) = auth.0.get_untracked() {
        spawn_local(async move {
            let list = fetch_list("containers?all=true", &tok).await;
            let running = running_ids(&list);
            containers.set(Some(list));

            let mut cpu_buckets: BTreeMap<i64, f64> = BTreeMap::new();
            let mut mem_buckets: BTreeMap<i64, f64> = BTreeMap::new();
            let mut seeded: HashMap<String, Vec<(f64, f64)>> = HashMap::new();

            for id in &running {
                let Ok(hist) = crate::api_client::fetch_metrics_history(id, None, &tok).await
                else {
                    continue;
                };
                let Some(samples) = hist.as_array() else {
                    continue;
                };
                let mut ring: Vec<(f64, f64)> = Vec::new();
                for s in samples {
                    let Some(ts) = s
                        .get("ts")
                        .and_then(Value::as_str)
                        .and_then(parse_rfc3339_epoch)
                    else {
                        continue;
                    };
                    let Some(cpu) = s.get("cpu_pct").and_then(Value::as_f64) else {
                        continue;
                    };
                    let cpu_pct = cpu * 100.0;
                    ring.push((ts as f64, cpu_pct));
                    *cpu_buckets.entry(ts).or_insert(0.0) += cpu_pct;
                    if let Some(mem) = s.get("mem_bytes").and_then(Value::as_f64) {
                        *mem_buckets.entry(ts).or_insert(0.0) += mem;
                    }
                }
                if !ring.is_empty() {
                    cap_ring(&mut ring);
                    seeded.insert(id.clone(), ring);
                }
            }

            // Seed per-container rings only where the live loop hasn't already
            // produced one (avoids clobbering fresher live samples).
            cpu_rings.update(|rings| {
                for (id, ring) in seeded {
                    rings.entry(id).or_insert(ring);
                }
            });

            let cpu_pts: Vec<(f64, f64)> = cpu_buckets
                .into_iter()
                .map(|(t, v)| (t as f64, v))
                .collect();
            let mem_pts: Vec<(f64, f64)> = mem_buckets
                .into_iter()
                .map(|(t, v)| (t as f64, v))
                .collect();
            merge_older(shared.agg_cpu, cpu_pts);
            merge_older(shared.agg_mem, mem_pts);
        });
    }

    // Append each poll tick's per-container CPU sample into the sparkline rings
    // so "top consumers" sparklines keep moving after the initial backfill.
    Effect::new(move |_| {
        let metrics = shared.latest_metrics.get();
        if metrics.is_empty() {
            return;
        }
        let now = js_sys::Date::now() / 1000.0;
        cpu_rings.update(|rings| {
            for (id, sample) in metrics.iter() {
                let ring = rings.entry(id.clone()).or_default();
                ring.push((now, sample.cpu_pct * 100.0));
                cap_ring(ring);
            }
        });
    });

    // ---- capacity donut (hero-donut, widest column) ---------------------
    let used_bytes = Signal::derive(move || df_used_reclaimable(&df.get()).0);
    let reclaimable_bytes = Signal::derive(move || df_used_reclaimable(&df.get()).1);
    let manage_disk = Callback::new(move |()| nav.0.set(Tab::Disk));

    // ---- hero-counts card values ----------------------------------------
    let containers_value =
        Signal::derive(move || format!("{}/{}", shared.running.get(), shared.total.get()));
    let containers_sub = Signal::derive(|| "running / total".to_string());

    let images_value = Signal::derive(move || match arr_len(&images.get()) {
        Some(c) => c.to_string(),
        None => match images.get() {
            Some(Err(_)) => "—".to_string(),
            _ => "…".to_string(),
        },
    });
    let images_sub = Signal::derive(move || {
        let size = df.get().and_then(|r| {
            r.ok()
                .and_then(|v| v.get("images").and_then(|i| i.get("size_bytes")).cloned())
                .and_then(|s| s.as_u64())
        });
        match size {
            Some(b) => format_bytes(b),
            None => "images".to_string(),
        }
    });

    let volumes_value = Signal::derive(move || count_label(&volumes.get()));
    let networks_value = Signal::derive(move || count_label(&networks.get()));
    let total_sub = Signal::derive(|| "total".to_string());

    let daemon_value = Signal::derive(move || match info.get() {
        Some(Ok(v)) => format!(
            "v{}",
            v.get("linpodx_version")
                .and_then(|s| s.as_str())
                .unwrap_or("?")
        ),
        Some(Err(_)) => "—".to_string(),
        None => "…".to_string(),
    });
    let daemon_sub = Signal::derive(move || match info.get() {
        Some(Ok(v)) => format!(
            "podman {}",
            v.get("podman_version")
                .and_then(|s| s.as_str())
                .unwrap_or("?")
        ),
        Some(Err(e)) => e,
        None => "loading".to_string(),
    });

    // ---- top consumers (top 3 running containers by cpu) -----------------
    let top_consumers = move || {
        let metrics = shared.latest_metrics.get();
        let names = id_name_map(&containers.get());
        let mut rows: Vec<(String, f64, f64)> = metrics
            .into_iter()
            .map(|(id, s)| (id, s.cpu_pct, s.mem_bytes))
            .collect();
        rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        rows.truncate(3);
        if rows.is_empty() {
            return view! {
                <div class="top-consumers__empty">"No running containers"</div>
            }
            .into_any();
        }
        rows.into_iter()
            .map(|(id, cpu, mem)| {
                let name = names.get(&id).cloned().unwrap_or_else(|| short_id(&id));
                let cpu_label = fmt_pct(cpu * 100.0);
                let mem_label = format_bytes(mem.max(0.0) as u64);
                let ring_id = id.clone();
                let data = Signal::derive(move || {
                    cpu_rings.get().get(&ring_id).cloned().unwrap_or_default()
                });
                let target = id.clone();
                let title = format!("Open {name}");
                view! {
                    <button
                        type="button"
                        class="top-consumers__row"
                        title=title
                        on:click=move |_| drawer.0.set(Some(target.clone()))
                    >
                        <span class="top-consumers__name">{name}</span>
                        <span class="top-consumers__spark">
                            <Sparkline data=data width=72.0 height=18.0/>
                        </span>
                        <span class="top-consumers__cpu mono">{cpu_label}</span>
                        <span class="top-consumers__mem mono cell-muted">{mem_label}</span>
                    </button>
                }
            })
            .collect_view()
            .into_any()
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
            <div class="hero-row">
                <div class="hero-donut">
                    <CapacityDonut
                        used_bytes=used_bytes
                        reclaimable_bytes=reclaimable_bytes
                        on_manage=manage_disk
                    />
                </div>
                <div class="hero-charts">
                    <AreaChart
                        data=Signal::derive(move || shared.agg_cpu.get())
                        title="CPU %".to_string()
                        height=64.0
                        value_fmt=fmt_pct
                        zero_floor=true
                    />
                    <AreaChart
                        data=Signal::derive(move || shared.agg_mem.get())
                        title="Memory".to_string()
                        height=64.0
                        value_fmt=fmt_mem
                        zero_floor=true
                    />
                </div>
                <div class="hero-counts">
                    {count_card(
                        "container",
                        "workloads",
                        "Containers",
                        Tab::Containers,
                        containers_value,
                        containers_sub,
                    )}
                    {count_card("image", "resources", "Images", Tab::Images, images_value, images_sub)}
                    {count_card(
                        "volume",
                        "resources",
                        "Volumes",
                        Tab::Volumes,
                        volumes_value,
                        total_sub,
                    )}
                    {count_card(
                        "network",
                        "resources",
                        "Networks",
                        Tab::Networks,
                        networks_value,
                        total_sub,
                    )}
                    {count_card("daemon", "system", "Daemon", Tab::Settings, daemon_value, daemon_sub)}
                </div>
            </div>

            <div class="hero-secondary">
                <LiveEvents/>
                <div class="quick-actions">
                    <div class="quick-actions__strip">
                        <button type="button" class="quick-action" on:click=new_container>
                            <span class="quick-action__icon"><Icon name="container"/></span>
                            <span class="quick-action__label">"New container"</span>
                        </button>
                        <button type="button" class="quick-action" on:click=run_doctor>
                            <span class="quick-action__icon"><Icon name="settings"/></span>
                            <span class="quick-action__label">"Doctor"</span>
                        </button>
                        <button type="button" class="quick-action" on:click=open_terminal>
                            <span class="quick-action__icon"><Icon name="sandbox"/></span>
                            <span class="quick-action__label">"Terminal"</span>
                        </button>
                        <button type="button" class="quick-action" on:click=on_refresh>
                            <span class="quick-action__icon"><Icon name="event"/></span>
                            <span class="quick-action__label">"Refresh"</span>
                        </button>
                    </div>
                    <div class="top-consumers">
                        <div class="top-consumers__head">"Top consumers"</div>
                        <div class="top-consumers__list">{top_consumers}</div>
                    </div>
                </div>
            </div>
        </div>
    }
}

/// Count label for a plain list response (volumes / networks): the array
/// length, `0` for a non-array OK body, `—` on error, `…` while loading.
fn count_label(res: &Option<Result<Value, String>>) -> String {
    match res {
        Some(Ok(Value::Array(a))) => a.len().to_string(),
        Some(Ok(_)) => "0".to_string(),
        Some(Err(_)) => "—".to_string(),
        None => "…".to_string(),
    }
}
