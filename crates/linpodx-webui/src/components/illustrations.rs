//! Spec v6 §6 — empty-state spot illustrations.
//!
//! Six self-authored, CC0, geometric inline-SVG motifs rendered at 96×96
//! through leptos' native SVG support (no `inner_html` / `set_html`, keeping
//! the crate's XSS-free posture — same convention as `icons.rs`). Structural
//! strokes use `currentColor` (`.empty-state__spot` sets that to the muted
//! tertiary text colour); the single highlight shape per motif carries the
//! `empty-spot__accent` class, which the `.section-scope--*` wrapper resolves
//! to `var(--section-fg)` so the illustration always reads in the host
//! panel's section hue. A low-opacity `var(--section-soft)` shape sits behind
//! each motif for depth — set as a plain fill attribute (never the accent
//! class, which would force it to full accent strength).
//!
//! Unknown motif names fall back to `"generic"` so a typo never blanks a
//! panel — same defensive posture as [`super::icons::Icon`].

use leptos::prelude::*;

/// Render a named empty-state spot illustration.
///
/// `motif` ∈ `"containers" | "images" | "volumes" | "networks" | "secrets" |
/// "generic"`; anything else falls back to `"generic"`.
#[component]
pub fn EmptySpot(#[prop(into)] motif: String) -> impl IntoView {
    match motif.as_str() {
        "containers" => view! {
            <svg viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <rect x="10" y="16" width="60" height="60" rx="14" fill="var(--section-soft)"></rect>
                <rect x="18" y="46" width="46" height="28" rx="5" stroke="currentColor" stroke-width="1.5" opacity="0.4"></rect>
                <rect x="26" y="34" width="46" height="28" rx="5" stroke="currentColor" stroke-width="1.5" opacity="0.65"></rect>
                <rect x="34" y="20" width="46" height="28" rx="5" stroke="currentColor" stroke-width="1.5"></rect>
                <path d="M34 25.5h46" class="empty-spot__accent" stroke-width="2.5" stroke-linecap="round"></path>
            </svg>
        }
        .into_any(),
        "images" => view! {
            <svg viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <ellipse cx="48" cy="52" rx="30" ry="20" fill="var(--section-soft)"></ellipse>
                <ellipse cx="48" cy="66" rx="27" ry="9" stroke="currentColor" stroke-width="1.5" opacity="0.4"></ellipse>
                <ellipse cx="48" cy="56" rx="27" ry="9" stroke="currentColor" stroke-width="1.5" opacity="0.65"></ellipse>
                <ellipse cx="48" cy="46" rx="27" ry="9" class="empty-spot__accent" fill-opacity="0.9" stroke="none"></ellipse>
            </svg>
        }
        .into_any(),
        "volumes" => view! {
            <svg viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <ellipse cx="48" cy="48" rx="32" ry="22" fill="var(--section-soft)"></ellipse>
                <path d="M22 30v36c0 5 11.6 9 26 9s26-4 26-9V30" stroke="currentColor" stroke-width="1.5"></path>
                <ellipse cx="48" cy="30" rx="26" ry="9" stroke="currentColor" stroke-width="1.5"></ellipse>
                <path d="M22 48c0 5 11.6 9 26 9s26-4 26-9" class="empty-spot__accent" fill="none" stroke-width="2.25" stroke-linecap="round"></path>
            </svg>
        }
        .into_any(),
        "networks" => view! {
            <svg viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <circle cx="48" cy="48" r="34" fill="var(--section-soft)"></circle>
                <path d="M48 27L25 63M48 27L71 63M27 66h42" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"></path>
                <circle cx="48" cy="22" r="7" stroke="currentColor" stroke-width="1.5"></circle>
                <circle cx="23" cy="66" r="7" stroke="currentColor" stroke-width="1.5"></circle>
                <circle cx="73" cy="66" r="7" stroke="currentColor" stroke-width="1.5"></circle>
                <circle cx="48" cy="50" r="9" class="empty-spot__accent" fill-opacity="0.9" stroke="none"></circle>
            </svg>
        }
        .into_any(),
        "secrets" => view! {
            <svg viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <rect x="14" y="20" width="68" height="56" rx="16" fill="var(--section-soft)"></rect>
                <rect x="27" y="46" width="42" height="32" rx="6" stroke="currentColor" stroke-width="1.5"></rect>
                <path d="M35 46V34a13 13 0 0 1 26 0v12" class="empty-spot__accent" fill="none" stroke-width="2.25" stroke-linecap="round"></path>
                <circle cx="48" cy="60" r="4.5" stroke="currentColor" stroke-width="1.5"></circle>
                <path d="M48 64.5v6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"></path>
            </svg>
        }
        .into_any(),
        _ => view! {
            <svg viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <rect x="16" y="16" width="64" height="64" rx="16" fill="var(--section-soft)"></rect>
                <rect
                    x="20" y="20" width="56" height="56" rx="12"
                    stroke="currentColor" stroke-width="1.5" stroke-dasharray="5 5"
                ></rect>
                <path d="M48 36v24M36 48h24" class="empty-spot__accent" stroke-width="2.5" stroke-linecap="round"></path>
            </svg>
        }
        .into_any(),
    }
}
