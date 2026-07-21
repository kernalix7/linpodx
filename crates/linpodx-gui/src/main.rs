//! Phase 24 (Tauri pivot) — linpodx-gui entrypoint.
//!
//! Boots a single Tauri window that loads a small bundled splash page, then (on
//! a background task) reaches the daemon — auto-spawning it if needed — and
//! navigates the webview to the daemon-served leptos Web UI. On failure the
//! splash's error state is shown with a Retry button wired to the
//! `retry_connect` command.

// The Tauri webview is the entire UI surface — no terminal window on release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    tracing::info!("linpodx-gui Tauri shell starting");

    if let Err(e) = run() {
        tracing::error!(error = %e, "tauri run failed");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![retry_connect])
        .setup(|app| {
            // Kick off the daemon-connect flow on Tauri's async runtime so the
            // window paints the splash immediately while we work in the
            // background.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                drive_connection(handle).await;
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("tauri run error: {e}"))
}

/// Command invoked by the splash's Retry button. Re-runs the connect flow.
#[tauri::command]
async fn retry_connect(app: tauri::AppHandle) {
    tracing::info!("retry_connect invoked from splash");
    drive_connection(app).await;
}

/// Reach the daemon (auto-spawn if needed), then navigate the main webview to
/// the daemon-served Web UI. On any failure, surface the error in the splash
/// via its `window.showError` hook so the user can retry.
async fn drive_connection(app: tauri::AppHandle) {
    match linpodx_gui::shell::ensure_ui_url().await {
        Ok(url) => {
            tracing::info!(url = %url, "navigating webview to daemon Web UI");
            if let Some(win) = app.get_webview_window("main") {
                let js = format!("window.location.replace({});", js_string(&url));
                if let Err(e) = win.eval(&js) {
                    tracing::error!(error = %e, "failed to navigate webview");
                }
            } else {
                tracing::error!("main webview window not found");
            }
        }
        Err(e) => {
            let msg = format!("{e:#}");
            tracing::warn!(error = %msg, "could not reach daemon");
            if let Some(win) = app.get_webview_window("main") {
                let js = format!("window.showError && window.showError({});", js_string(&msg));
                let _ = win.eval(&js);
            }
        }
    }
}

/// Encode `s` as a safe JavaScript/JSON string literal (quotes + escaping) so it
/// can be interpolated into an `eval`'d snippet without injection risk.
fn js_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}
