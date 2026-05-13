# ADR 0004 — iced 0.13 for the desktop GUI

- **Status**: Accepted (2026-05, Phase 1B)
- **Deciders**: kernalix7

## Context

The desktop GUI sits next to the CLI as a first-class client. Options considered:

- **Tauri**: HTML/JS frontend in a webview + Rust backend. Two languages, webview
  baggage, and Wayland support is uneven on Linux.
- **GTK4 (gtk-rs)**: native LGPL bindings, mature, but requires C library at build
  time and a non-trivial async story to bridge with tokio.
- **iced 0.13**: pure Rust, MIT, Elm-style architecture, bring-your-own-runtime. Wgpu
  renderer works on Wayland and X11 without extra system deps.
- **slint**: dual-licensed; commercial restriction is incompatible with MIT-only goal.

## Decision

Use iced 0.13 with the `tokio` feature enabled. The GUI is a thin event-bus subscriber
that re-renders on every event the daemon broadcasts.

## Consequences

**Positive:**
- Pure-Rust dependency — no system GTK/Qt/WebView2.
- The Elm-style `Message`/`update`/`view` loop maps cleanly onto our event-stream
  semantics (each `event` from the daemon is a `Message`).
- One license, MIT. Compatible with our MIT-only goal in `deny.toml`.
- Same iced primitives can later be used for an embedded TUI/dashboard surface.

**Negative:**
- Cold compile is heavy (~2 min on first build). Cached after that.
- Theming/widget set is younger than GTK; some advanced widgets (DataGrid) need to be
  built ourselves.
- Wayland HiDPI works but is sometimes blurry under fractional scaling — wgpu issue,
  not iced.
