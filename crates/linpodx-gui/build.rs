//! Phase 24 (Tauri pivot) — Tauri build glue.
//!
//! The cxx-qt + Qt 6 direction was cancelled (licensing + velocity). The GUI is
//! now a thin Tauri 2 shell whose webview displays the daemon-served leptos Web
//! UI. `tauri_build::build()` reads `tauri.conf.json`, generates the runtime
//! context, and emits the platform metadata Tauri needs at compile time.
fn main() {
    tauri_build::build();
}
