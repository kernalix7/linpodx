//! Inline SVG icon set — self-authored CC0 24×24 `currentColor` strokes,
//! ported from `linpodx-gui/assets/icons/*.svg`.
//!
//! Rendered through the leptos `view!` macro's native SVG support (no
//! `inner_html` / `set_html`, keeping the crate's XSS-free posture). Every
//! glyph inherits `currentColor`, so colour is controlled entirely by the CSS
//! `color` of the surrounding element; sizing comes from the host element's
//! `width` / `height`.
//!
//! Use [`Icon`] with a stable name; unknown names fall back to a neutral dot so
//! a typo never blanks a control.

use leptos::prelude::*;

/// Render a named icon. `name` matches the source SVG basenames plus a few
/// UI-only glyphs (`chevron`, `chevron-left`, `close`).
#[component]
pub fn Icon(#[prop(into)] name: String) -> impl IntoView {
    // Common stroke attributes are repeated per branch because the leptos
    // `view!` macro needs the literal `<svg>` element to attach the SVG
    // namespace; factoring the wrapper out would lose that.
    match name.as_str() {
        "container" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3" y="6" width="18" height="13" rx="1.5"></rect>
                <path d="M3 10h18"></path>
                <path d="M8 6V4"></path>
                <path d="M16 6V4"></path>
                <path d="M8 14h2"></path>
                <path d="M14 14h2"></path>
            </svg>
        }
        .into_any(),
        "image" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3" y="4" width="18" height="16" rx="2"></rect>
                <circle cx="9" cy="10" r="1.75"></circle>
                <path d="M3 17l5-5 4 4 3-3 6 6"></path>
            </svg>
        }
        .into_any(),
        "volume" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <ellipse cx="12" cy="6" rx="8" ry="3"></ellipse>
                <path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6"></path>
                <path d="M4 12v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"></path>
            </svg>
        }
        .into_any(),
        "network" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M3 12h18"></path>
                <path d="M12 3a13 13 0 0 1 0 18"></path>
                <path d="M12 3a13 13 0 0 0 0 18"></path>
            </svg>
        }
        .into_any(),
        // Stacks tab (compose-project grouping) — layered rectangles.
        "stack" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 3l9 4.5-9 4.5-9-4.5 9-4.5z"></path>
                <path d="M3 12l9 4.5 9-4.5"></path>
                <path d="M3 16.5l9 4.5 9-4.5"></path>
            </svg>
        }
        .into_any(),
        // Pods tab — a shared network namespace grouping containers, drawn as
        // an outer capsule with two member containers inside.
        "pod" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="2.5" y="5" width="19" height="14" rx="4"></rect>
                <rect x="6" y="9" width="5" height="6" rx="1"></rect>
                <rect x="13" y="9" width="5" height="6" rx="1"></rect>
            </svg>
        }
        .into_any(),
        "snapshot" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M5 7h2l1.5-2h7L17 7h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z"></path>
                <circle cx="12" cy="13" r="3.5"></circle>
            </svg>
        }
        .into_any(),
        "sandbox" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6l-8-4z"></path>
                <path d="M9 12l2 2 4-4"></path>
            </svg>
        }
        .into_any(),
        "event" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z"></path>
            </svg>
        }
        .into_any(),
        "pin" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M9 3h6l-1 5 3 3v3H7v-3l3-3-1-5z"></path>
                <path d="M12 14v7"></path>
            </svg>
        }
        .into_any(),
        "plugin" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M9 3v4"></path>
                <path d="M15 3v4"></path>
                <path d="M6 7h12v5a4 4 0 0 1-4 4h-1v5h-2v-5h-1a4 4 0 0 1-4-4V7z"></path>
            </svg>
        }
        .into_any(),
        "settings" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="3"></circle>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.39.16.74.45 1 .82.26.37.4.81.4 1.27V12a2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
        }
        .into_any(),
        "search" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="10.5" cy="10.5" r="6.5"></circle>
                <path d="M20 20l-4.8-4.8"></path>
            </svg>
        }
        .into_any(),
        "theme-dark" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"></path>
            </svg>
        }
        .into_any(),
        "theme-light" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="4"></circle>
                <path d="M12 2v2"></path>
                <path d="M12 20v2"></path>
                <path d="M2 12h2"></path>
                <path d="M20 12h2"></path>
                <path d="M4.93 4.93l1.41 1.41"></path>
                <path d="M17.66 17.66l1.41 1.41"></path>
                <path d="M4.93 19.07l1.41-1.41"></path>
                <path d="M17.66 6.34l1.41-1.41"></path>
            </svg>
        }
        .into_any(),
        "daemon" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3" y="4" width="18" height="7" rx="1.5"></rect>
                <rect x="3" y="13" width="18" height="7" rx="1.5"></rect>
                <circle cx="7" cy="7.5" r="0.6" fill="currentColor"></circle>
                <circle cx="7" cy="16.5" r="0.6" fill="currentColor"></circle>
                <path d="M11 7.5h6"></path>
                <path d="M11 16.5h6"></path>
            </svg>
        }
        .into_any(),
        "approval" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M8 12.5l3 3 5-6"></path>
            </svg>
        }
        .into_any(),
        "chevron" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M6 9l6 6 6-6"></path>
            </svg>
        }
        .into_any(),
        "chevron-left" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M15 6l-6 6 6 6"></path>
            </svg>
        }
        .into_any(),
        // Section-header disclosure chevron (points down when open; the shell
        // rotates it -90° via CSS when the section is collapsed). Alias of
        // "chevron" so §1.3's `name="chevron-down"` resolves to a real glyph.
        "chevron-down" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M6 9l6 6 6-6"></path>
            </svg>
        }
        .into_any(),
        // Disk / disk-usage tabs (System group) — a drive drum with a spindle
        // hub, distinct from the "volume" cylinder so the two never read alike.
        "disk" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="3" y="6" width="18" height="12" rx="2"></rect>
                <circle cx="16.5" cy="12" r="1.6"></circle>
                <path d="M6 12h6"></path>
            </svg>
        }
        .into_any(),
        // Secrets tab / empty-spot motif — a padlock with keyhole. The shackle
        // arc reads as the accent shape when tinted.
        "secret" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="5" y="10" width="14" height="10" rx="2"></rect>
                <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
                <circle cx="12" cy="15" r="1.4"></circle>
            </svg>
        }
        .into_any(),
        "close" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
                stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M6 6l12 12"></path>
                <path d="M18 6l-12 12"></path>
            </svg>
        }
        .into_any(),
        // Fallback: neutral filled dot — an unknown name never blanks a control.
        _ => view! {
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <circle cx="12" cy="12" r="4"></circle>
            </svg>
        }
        .into_any(),
    }
}
