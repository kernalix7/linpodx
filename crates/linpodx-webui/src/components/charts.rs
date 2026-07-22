//! Inline-SVG chart primitives — no external JS chart library.
//!
//! Every primitive is a thin leptos wrapper over the pure geometry functions in
//! [`crate::helpers`] (`project_series` / `line_path` / `area_path` / …), which
//! carry the unit-tested path math. The components here only wire those strings
//! into reactive `<svg>` attributes and add the hover layer.
//!
//! Dataviz contract (project standard):
//!   * one y-axis per chart, never dual-axis;
//!   * lines 2px, area fills use the accent token at low alpha;
//!   * grid / axes recessive (border token); text uses the text tokens, never
//!     the series colour;
//!   * single series → titled header, no legend; two series → 2 FIXED hues
//!     (accent + info) with a small legend;
//!   * status colours (success/warn/danger) are reserved for state, never used
//!     as series colours;
//!   * every plot ships a hover layer: a crosshair + tooltip (timestamp +
//!     value), driven by transparent hit-rects wider than the mark;
//!   * dark / light entirely via the existing CSS tokens.

use leptos::prelude::*;

use crate::helpers::{
    area_path, clock_hms, line_path, project_point, project_series, ts_bounds, value_bounds,
};

/// Fixed viewBox width; the SVG scales to its container via `width: 100%` +
/// `preserveAspectRatio="none"`, so this is just the internal coordinate span.
const VW: f64 = 600.0;
const PAD: f64 = 8.0;

/// Default value formatter — one decimal place.
fn default_fmt(v: f64) -> String {
    format!("{v:.1}")
}

/// Shared hover overlay: transparent hit-rects (one per sample, wider than the
/// mark) drive a `RwSignal<Option<usize>>`; a crosshair + tooltip render off it.
/// Returns the overlay view. `coords` are the projected points; `data` supplies
/// the raw `(ts, value)` for the tooltip.
fn hover_overlay(
    coords: Memo<Vec<(f64, f64)>>,
    data: Signal<Vec<(f64, f64)>>,
    hover: RwSignal<Option<usize>>,
    height: f64,
    value_fmt: fn(f64) -> String,
) -> impl IntoView {
    let hit_rects = move || {
        let pts = coords.get();
        let n = pts.len().max(1);
        let slot = VW / n as f64;
        pts.into_iter()
            .enumerate()
            .map(|(i, (x, _))| {
                view! {
                    <rect
                        x=move || (x - slot / 2.0).max(0.0)
                        y="0"
                        width=slot
                        height=height
                        fill="transparent"
                        style="cursor:crosshair"
                        on:mouseenter=move |_| hover.set(Some(i))
                    ></rect>
                }
            })
            .collect_view()
    };

    let crosshair = move || match hover.get() {
        None => view! { <g></g> }.into_any(),
        Some(i) => {
            let pts = coords.get();
            let raw = data.get();
            let (cx, cy) = match pts.get(i) {
                Some(&p) => p,
                None => return view! { <g></g> }.into_any(),
            };
            let (ts, val) = raw.get(i).copied().unwrap_or((0.0, 0.0));
            let label_time = clock_hms(ts as i64);
            let label_val = value_fmt(val);
            // Clamp the tooltip box so it never overflows the viewBox.
            let box_w = 118.0_f64;
            let tx = (cx - box_w / 2.0).clamp(2.0, VW - box_w - 2.0);
            view! {
                <g class="chart-hover">
                    <line
                        class="chart-crosshair"
                        x1=cx
                        y1=PAD
                        x2=cx
                        y2=height - PAD
                    ></line>
                    <circle class="chart-dot" cx=cx cy=cy r="3"></circle>
                    <g transform=format!("translate({tx:.1},4)")>
                        <rect class="chart-tip" x="0" y="0" width=box_w height="34" rx="4"></rect>
                        <text class="chart-tip__time" x="8" y="14">{label_time}</text>
                        <text class="chart-tip__val" x=box_w - 8.0 y="27">{label_val}</text>
                    </g>
                </g>
            }
            .into_any()
        }
    };

    view! {
        <g class="chart-hit" on:mouseleave=move |_| hover.set(None)>
            {hit_rects}
            {crosshair}
        </g>
    }
}

/// Titled, filled single-series area chart with the current value as the card's
/// big number. History is the area; hover reveals per-sample values.
#[component]
pub fn AreaChart(
    #[prop(into)] data: Signal<Vec<(f64, f64)>>,
    #[prop(into)] title: String,
    #[prop(default = 120.0)] height: f64,
    #[prop(default = default_fmt)] value_fmt: fn(f64) -> String,
    #[prop(default = true)] zero_floor: bool,
) -> impl IntoView {
    let hover = RwSignal::new(None::<usize>);
    let coords = Memo::new(move |_| project_series(&data.get(), VW, height, PAD, zero_floor));
    let area_d = move || area_path(&coords.get(), height - PAD);
    let line_d = move || line_path(&coords.get());
    let current = move || {
        data.get()
            .last()
            .map(|&(_, v)| value_fmt(v))
            .unwrap_or_else(|| "—".to_string())
    };
    let vb = move || format!("0 0 {VW} {height}");
    view! {
        <div class="chart-card">
            <div class="chart-card__head">
                <span class="chart-card__title">{title}</span>
                <span class="chart-card__value mono">{current}</span>
            </div>
            <svg
                class="spark-area"
                viewBox=vb
                preserveAspectRatio="none"
                role="img"
            >
                <path class="spark-area__fill" d=area_d></path>
                <path class="spark-line" d=line_d></path>
                {move || hover_overlay(coords, data, hover, height, value_fmt)}
            </svg>
        </div>
    }
}

/// Titled single-series line chart (no fill). Same hover contract as
/// [`AreaChart`]; used where the fill would imply an area semantic (e.g. CPU%).
///
/// Consumed by the container-drawer Stats tab (parallel agent); allow the
/// props to read as dead until that call-site lands.
#[allow(dead_code)]
#[component]
pub fn LineChart(
    #[prop(into)] data: Signal<Vec<(f64, f64)>>,
    #[prop(into)] title: String,
    #[prop(default = 120.0)] height: f64,
    #[prop(default = default_fmt)] value_fmt: fn(f64) -> String,
    #[prop(default = false)] zero_floor: bool,
) -> impl IntoView {
    let hover = RwSignal::new(None::<usize>);
    let coords = Memo::new(move |_| project_series(&data.get(), VW, height, PAD, zero_floor));
    let line_d = move || line_path(&coords.get());
    let current = move || {
        data.get()
            .last()
            .map(|&(_, v)| value_fmt(v))
            .unwrap_or_else(|| "—".to_string())
    };
    let vb = move || format!("0 0 {VW} {height}");
    view! {
        <div class="chart-card">
            <div class="chart-card__head">
                <span class="chart-card__title">{title}</span>
                <span class="chart-card__value mono">{current}</span>
            </div>
            <svg class="spark-area" viewBox=vb preserveAspectRatio="none" role="img">
                <path class="spark-line" d=line_d></path>
                {move || hover_overlay(coords, data, hover, height, value_fmt)}
            </svg>
        </div>
    }
}

/// Two-series line chart on a SHARED y-axis (rx / tx throughput). Fixed hues:
/// series A = accent, series B = info. Small legend, never cycled colours.
///
/// Consumed by the container-drawer Stats tab (parallel agent); allow the
/// props to read as dead until that call-site lands.
#[allow(dead_code)]
#[component]
pub fn TwoSeriesChart(
    #[prop(into)] series_a: Signal<Vec<(f64, f64)>>,
    #[prop(into)] series_b: Signal<Vec<(f64, f64)>>,
    #[prop(into)] title: String,
    #[prop(into)] label_a: String,
    #[prop(into)] label_b: String,
    #[prop(default = 120.0)] height: f64,
    #[prop(default = default_fmt)] value_fmt: fn(f64) -> String,
) -> impl IntoView {
    // Shared bounds so both series read against one y-axis.
    let both = Memo::new(move |_| {
        let mut v = series_a.get();
        v.extend(series_b.get());
        v
    });
    let coords_a = Memo::new(move |_| {
        let tb = ts_bounds(&both.get());
        let vb = value_bounds(&both.get(), true);
        series_a
            .get()
            .iter()
            .map(|&(t, val)| project_point(t, val, tb, vb, VW, height, PAD))
            .collect::<Vec<_>>()
    });
    let coords_b = Memo::new(move |_| {
        let tb = ts_bounds(&both.get());
        let vb = value_bounds(&both.get(), true);
        series_b
            .get()
            .iter()
            .map(|&(t, val)| project_point(t, val, tb, vb, VW, height, PAD))
            .collect::<Vec<_>>()
    });
    let line_a = move || line_path(&coords_a.get());
    let line_b = move || line_path(&coords_b.get());
    let cur_a = move || {
        series_a
            .get()
            .last()
            .map(|&(_, v)| value_fmt(v))
            .unwrap_or_else(|| "—".to_string())
    };
    let cur_b = move || {
        series_b
            .get()
            .last()
            .map(|&(_, v)| value_fmt(v))
            .unwrap_or_else(|| "—".to_string())
    };
    let vb = move || format!("0 0 {VW} {height}");

    // Shared hover: hit-rects over series A positions drive a crosshair + a
    // tooltip showing the timestamp and BOTH series values at that index.
    let hover = RwSignal::new(None::<usize>);
    let hit_rects = move || {
        let pts = coords_a.get();
        let n = pts.len().max(1);
        let slot = VW / n as f64;
        pts.into_iter()
            .enumerate()
            .map(|(i, (x, _))| {
                view! {
                    <rect
                        x=move || (x - slot / 2.0).max(0.0)
                        y="0"
                        width=slot
                        height=height
                        fill="transparent"
                        style="cursor:crosshair"
                        on:mouseenter=move |_| hover.set(Some(i))
                    ></rect>
                }
            })
            .collect_view()
    };
    let crosshair = move || match hover.get() {
        None => view! { <g></g> }.into_any(),
        Some(i) => {
            let pa = coords_a.get();
            let cx = match pa.get(i) {
                Some(&(x, _)) => x,
                None => return view! { <g></g> }.into_any(),
            };
            let ra = series_a.get();
            let rb = series_b.get();
            let ts = ra.get(i).map(|&(t, _)| t).unwrap_or(0.0);
            let va = ra.get(i).map(|&(_, v)| value_fmt(v)).unwrap_or_default();
            let vb2 = rb.get(i).map(|&(_, v)| value_fmt(v)).unwrap_or_default();
            let box_w = 150.0_f64;
            let tx = (cx - box_w / 2.0).clamp(2.0, VW - box_w - 2.0);
            view! {
                <g class="chart-hover">
                    <line class="chart-crosshair" x1=cx y1=PAD x2=cx y2=height - PAD></line>
                    <g transform=format!("translate({tx:.1},4)")>
                        <rect class="chart-tip" x="0" y="0" width=box_w height="34" rx="4"></rect>
                        <text class="chart-tip__time" x="8" y="14">{clock_hms(ts as i64)}</text>
                        <text class="chart-tip__val" x=box_w - 8.0 y="14">{va}</text>
                        <text class="chart-tip__val" x=box_w - 8.0 y="28">{vb2}</text>
                    </g>
                </g>
            }
            .into_any()
        }
    };

    view! {
        <div class="chart-card">
            <div class="chart-card__head">
                <span class="chart-card__title">{title}</span>
            </div>
            <div class="chart-legend">
                <span class="chart-legend__item">
                    <span class="chart-legend__swatch chart-legend__swatch--a"></span>
                    {label_a}" "<span class="mono">{cur_a}</span>
                </span>
                <span class="chart-legend__item">
                    <span class="chart-legend__swatch chart-legend__swatch--b"></span>
                    {label_b}" "<span class="mono">{cur_b}</span>
                </span>
            </div>
            <svg class="spark-area" viewBox=vb preserveAspectRatio="none" role="img">
                <path class="spark-line spark-line--a" d=line_a></path>
                <path class="spark-line spark-line--b" d=line_b></path>
                <g class="chart-hit" on:mouseleave=move |_| hover.set(None)>
                    {hit_rects}
                    {crosshair}
                </g>
            </svg>
        </div>
    }
}

/// Minimal sparkline for the status footer — no header, axes or hover, just a
/// filled micro-area. Sized by its container (`width`/`height` props default to
/// the 64×16 footer slot).
#[component]
pub fn Sparkline(
    #[prop(into)] data: Signal<Vec<(f64, f64)>>,
    #[prop(default = 64.0)] width: f64,
    #[prop(default = 16.0)] height: f64,
) -> impl IntoView {
    let coords = Memo::new(move |_| project_series(&data.get(), width, height, 1.0, true));
    let area_d = move || area_path(&coords.get(), height - 1.0);
    let line_d = move || line_path(&coords.get());
    let vb = move || format!("0 0 {width} {height}");
    view! {
        <svg class="statusbar-spark" viewBox=vb preserveAspectRatio="none" aria-hidden="true">
            <path class="spark-area__fill" d=area_d></path>
            <path class="spark-line" d=line_d></path>
        </svg>
    }
}
