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
    area_path, clock_hms, format_bytes, line_path, project_point, project_series, ts_bounds,
    value_bounds,
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
                // Vertical accent gradient (18% → 2% alpha) so the filled shape
                // reads as a solid mass rather than a flat wash — the fill, not
                // the 1px line, is what the eye lands on (defect: shapeless plot).
                <defs>
                    <linearGradient id="spark-area-grad" x1="0" y1="0" x2="0" y2="1">
                        <stop
                            offset="0%"
                            stop-color="var(--color-accent)"
                            stop-opacity="0.18"
                        ></stop>
                        <stop
                            offset="100%"
                            stop-color="var(--color-accent)"
                            stop-opacity="0.02"
                        ></stop>
                    </linearGradient>
                </defs>
                <path class="spark-area__fill spark-area__fill--grad" d=area_d></path>
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

// ---------------------------------------------------------------------------
// Capacity donut (Spec v6 §4 hero-donut) — pure ring geometry + a thin leptos
// wrapper. Draws the ring as stacked `<circle>` elements offset via
// `stroke-dasharray`/`stroke-dashoffset` (the standard SVG donut technique)
// rather than hand-rolled arc paths — it sidesteps the large-arc-flag edge
// cases of `A` path commands while staying just as "pure path math".
//
// Dataviz contract for this specific chart (per spec, an intentional, scoped
// exception to the single-sequential-hue donut rule elsewhere in the house
// style): Used = the System section hue (`--sec-system-fg`) since its CTA
// routes to the System-section Disk tab; Reclaimable = the warn hue (an
// explicit, spec-directed use of a status colour, not an accidental one). The
// ring is two-segment only — `system df` has no host-capacity field to derive
// a real "free" number from, so we never draw or legend a fabricated "free"
// slice. The centre label is the tracked total (`used + reclaimable`).

/// One ring segment's precomputed stroke geometry. Pure function output — no
/// leptos/DOM involved — so [`donut_segments`] is unit-testable on the host
/// target.
#[derive(Clone, Debug, PartialEq)]
pub struct DonutSegment {
    /// `"{dash} {gap}"`, ready for the `stroke-dasharray` attribute.
    pub dasharray: String,
    /// Negative offset (along the circumference) at which this segment's
    /// dash begins, for the `stroke-dashoffset` attribute.
    pub dashoffset: f64,
    /// This segment's share of `total`, clamped to `[0, 1]`.
    pub fraction: f64,
}

/// Circumference of a ring of the given radius — `2πr`.
pub fn donut_circumference(radius: f64) -> f64 {
    2.0 * std::f64::consts::PI * radius
}

/// Lay `values` end-to-end around a ring of `circumference`, starting at the
/// 12-o'clock position (the caller applies a `rotate(-90 cx cy)` transform to
/// the group). Negative inputs clamp to zero rather than reversing direction;
/// a non-positive `total` or `circumference` yields empty (zero-length,
/// zero-fraction) segments instead of `NaN`/`Inf` so a still-loading chart
/// never emits an invalid SVG attribute.
pub fn donut_segments(values: &[f64], total: f64, circumference: f64) -> Vec<DonutSegment> {
    if total <= 0.0 || circumference <= 0.0 {
        return values
            .iter()
            .map(|_| DonutSegment {
                dasharray: format!("0 {circumference:.3}"),
                dashoffset: 0.0,
                fraction: 0.0,
            })
            .collect();
    }
    let mut cum = 0.0_f64;
    values
        .iter()
        .map(|&raw| {
            let v = raw.max(0.0);
            let fraction = (v / total).clamp(0.0, 1.0);
            let seg_len = fraction * circumference;
            let gap_len = (circumference - seg_len).max(0.0);
            let dashoffset = -(cum / total) * circumference;
            cum += v;
            DonutSegment {
                dasharray: format!("{seg_len:.3} {gap_len:.3}"),
                dashoffset,
                fraction,
            }
        })
        .collect()
}

/// Hero capacity ring: `Used` (system-section hue) + `Reclaimable` (warn hue)
/// arcs over a neutral track, a center byte total, a 2-row legend, and an
/// optional "Manage disk →" CTA. Self-contained (no outer card chrome) so it
/// can be dropped straight into `.hero-donut` on the dashboard *or* re-sized
/// into a smaller card elsewhere (e.g. the disk center's own summary card) —
/// the caller supplies the outer wrapper element and its styling.
#[component]
pub fn CapacityDonut(
    #[prop(into)] used_bytes: Signal<u64>,
    #[prop(into)] reclaimable_bytes: Signal<u64>,
    #[prop(default = 64.0)] radius: f64,
    #[prop(default = 16.0)] stroke_width: f64,
    /// Fires when the CTA is clicked; omit to render without a CTA (e.g. when
    /// already on the page the CTA would navigate to).
    #[prop(optional)]
    on_manage: Option<Callback<()>>,
) -> impl IntoView {
    let circumference = donut_circumference(radius);
    let size = 2.0 * (radius + stroke_width);
    let center = radius + stroke_width;
    let vb = format!("0 0 {size} {size}");
    let rotate = format!("rotate(-90 {center} {center})");

    let segments = Memo::new(move |_| {
        let used = used_bytes.get() as f64;
        let reclaim = reclaimable_bytes.get() as f64;
        donut_segments(&[used, reclaim], used + reclaim, circumference)
    });
    let seg_attr = move |i: usize| {
        segments.get().get(i).cloned().unwrap_or(DonutSegment {
            dasharray: format!("0 {circumference:.3}"),
            dashoffset: 0.0,
            fraction: 0.0,
        })
    };
    let used_dasharray = move || seg_attr(0).dasharray;
    let used_dashoffset = move || seg_attr(0).dashoffset;
    let reclaim_dasharray = move || seg_attr(1).dasharray;
    let reclaim_dashoffset = move || seg_attr(1).dashoffset;

    let total_label =
        move || format_bytes(used_bytes.get().saturating_add(reclaimable_bytes.get()));

    view! {
        <>
            <svg
                class="hero-donut__ring"
                viewBox=vb
                role="img"
                aria-label="Disk capacity: used and reclaimable space"
            >
                <circle
                    cx=center
                    cy=center
                    r=radius
                    fill="none"
                    stroke="var(--color-border-strong)"
                    stroke-width=stroke_width
                ></circle>
                <g transform=rotate>
                    <circle
                        cx=center
                        cy=center
                        r=radius
                        fill="none"
                        stroke="var(--sec-system-fg)"
                        stroke-width=stroke_width
                        stroke-dasharray=used_dasharray
                        stroke-dashoffset=used_dashoffset
                    ></circle>
                    <circle
                        cx=center
                        cy=center
                        r=radius
                        fill="none"
                        stroke="var(--color-warn)"
                        stroke-width=stroke_width
                        stroke-dasharray=reclaim_dasharray
                        stroke-dashoffset=reclaim_dashoffset
                    ></circle>
                </g>
                <text class="hero-donut__center" x=center y=center dy="0.35em">
                    {total_label}
                </text>
            </svg>
            <div class="hero-donut__legend">
                <div class="hero-donut__legend-row">
                    <span
                        class="hero-donut__swatch"
                        style="background: var(--sec-system-fg)"
                    ></span>
                    "Used "<span class="mono">{move || format_bytes(used_bytes.get())}</span>
                </div>
                <div class="hero-donut__legend-row">
                    <span class="hero-donut__swatch" style="background: var(--color-warn)"></span>
                    "Reclaimable "
                    <span class="mono">{move || format_bytes(reclaimable_bytes.get())}</span>
                </div>
            </div>
            {move || {
                on_manage.map(|cb| {
                    view! {
                        <button type="button" class="hero-donut__cta" on:click=move |_| cb.run(())>
                            "Manage disk →"
                        </button>
                    }
                })
            }}
        </>
    }
}

// NB: this file's `#[cfg(test)]` module below only compiles for
// `wasm32-unknown-unknown` (see `lib.rs`'s `#[cfg(target_arch = "wasm32")]
// mod components;`), so host-target `cargo test -p linpodx-webui` never sees
// it — same convention already used in `stacks.rs` / `secrets.rs`. It still
// pulls its weight: `cargo clippy -p linpodx-webui --target
// wasm32-unknown-unknown --all-targets -- -D warnings` compiles and lints it,
// and it documents/exercises the pure ring math for anyone building against
// this crate on that target.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circumference_matches_2_pi_r() {
        let c = donut_circumference(10.0);
        assert!((c - 62.831_853).abs() < 1e-3);
    }

    #[test]
    fn zero_radius_yields_zero_circumference() {
        assert_eq!(donut_circumference(0.0), 0.0);
    }

    #[test]
    fn segments_split_proportionally_starting_at_zero_offset() {
        let segs = donut_segments(&[50.0, 30.0, 20.0], 100.0, 100.0);
        assert_eq!(segs.len(), 3);
        assert!((segs[0].fraction - 0.5).abs() < 1e-9);
        assert!((segs[1].fraction - 0.3).abs() < 1e-9);
        assert!((segs[2].fraction - 0.2).abs() < 1e-9);
        assert_eq!(segs[0].dashoffset, 0.0);
        assert!((segs[1].dashoffset - (-50.0)).abs() < 1e-9);
        assert!((segs[2].dashoffset - (-80.0)).abs() < 1e-9);
        assert_eq!(segs[0].dasharray, "50.000 50.000");
        assert_eq!(segs[1].dasharray, "30.000 70.000");
        assert_eq!(segs[2].dasharray, "20.000 80.000");
    }

    #[test]
    fn zero_total_yields_empty_ring_not_nan_or_inf() {
        let segs = donut_segments(&[5.0, 5.0], 0.0, 100.0);
        assert_eq!(segs.len(), 2);
        for s in &segs {
            assert_eq!(s.fraction, 0.0);
            assert_eq!(s.dasharray, "0 100.000");
            assert!(s.dashoffset.is_finite());
        }
    }

    #[test]
    fn non_positive_circumference_still_returns_finite_segments() {
        let segs = donut_segments(&[5.0, 5.0], 10.0, 0.0);
        assert_eq!(segs.len(), 2);
        for s in &segs {
            assert_eq!(s.dasharray, "0 0.000");
        }
    }

    #[test]
    fn negative_values_clamp_to_zero_rather_than_reversing() {
        let segs = donut_segments(&[-10.0, 20.0], 20.0, 62.8);
        assert_eq!(segs[0].fraction, 0.0);
        assert!((segs[1].fraction - 1.0).abs() < 1e-9);
        // A negative raw value must not shift the *next* segment's start —
        // it contributes 0 to the running sum, same as if it were absent.
        assert_eq!(segs[1].dashoffset, 0.0);
    }

    #[test]
    fn fractions_sum_to_one_when_total_is_fully_accounted_for() {
        let segs = donut_segments(&[33.0, 33.0, 34.0], 100.0, 200.0);
        let sum: f64 = segs.iter().map(|s| s.fraction).sum();
        assert!((sum - 1.0).abs() < 1e-9);
    }
}
