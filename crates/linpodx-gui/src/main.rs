//! Phase 24 Stage 1 — linpodx-gui Qt 6 entrypoint.
//!
//! Boots a `QApplication`, constructs the `MainWindow` shell (sidebar + 11
//! stacked pages + banner + timeline), shows it, and runs the Qt event loop.
//! The daemon IPC worker (tokio) is spun up on a background thread and bridged
//! to the UI in Stage 1.5; Stage 1 proves the shell renders and switches tabs.

use cxx_qt_lib_extras::QApplication;
use linpodx_gui::ffi::ffi;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    tracing::info!("linpodx-gui Phase 24 (cxx-qt + Qt 6) starting");

    let mut app = QApplication::new();
    let mut window = ffi::new_main_window();

    if let Some(w) = window.as_mut() {
        ffi::show_window(w);
    } else {
        tracing::error!("failed to construct MainWindow");
        std::process::exit(1);
    }

    let code = match app.as_mut() {
        Some(a) => a.exec(),
        None => {
            tracing::error!("failed to construct QApplication");
            1
        }
    };
    std::process::exit(code);
}
