//! Phase 24 — cxx bridge to the Qt 6 `MainWindow` shell (`src/cpp/mainwindow.*`).
//!
//! Plain `#[cxx::bridge]` (not a cxx-qt QObject bridge) because the Stage 1
//! shell only needs to construct the window, show it, and push banner/timeline
//! updates. The state-driven QObject controller lands in Stage 1.5.

#[cxx::bridge(namespace = "linpodx")]
#[allow(clippy::module_inception)] // cxx::bridge requires the inner `mod ffi`.
pub mod ffi {
    unsafe extern "C++" {
        include!("linpodx-gui/src/cpp/mainwindow.h");

        type MainWindow;

        fn new_main_window() -> UniquePtr<MainWindow>;
        fn show_window(w: Pin<&mut MainWindow>);
        fn set_banner(w: Pin<&mut MainWindow>, text: &str, kind: i32);
        fn push_timeline(w: Pin<&mut MainWindow>, line: &str);
        fn set_active_tab(w: Pin<&mut MainWindow>, index: i32);
        fn active_tab(w: &MainWindow) -> i32;
    }
}
