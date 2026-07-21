//! Phase 24 — cxx-qt build glue.
//!
//! Registers the `ffi` cxx bridge and compiles the hand-written Qt C++ shell
//! (`src/cpp/mainwindow.cpp`). Qt Core/Gui/Widgets are linked so `QString`,
//! `QApplication`, `QMainWindow`, and the widget tree resolve.

fn main() {
    let builder = cxx_qt_build::CxxQtBuilder::new()
        .qt_module("Core")
        .qt_module("Gui")
        .qt_module("Widgets")
        .file("src/ffi.rs");

    // SAFETY: we only register our own hand-written C++ shell + include dir.
    // No build-flag mutation that would break cxx-qt's own codegen.
    let builder = unsafe {
        builder.cc_builder(|cc| {
            cc.file("src/cpp/mainwindow.cpp");
            cc.include("src/cpp");
        })
    };

    builder.build();

    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/cpp/mainwindow.cpp");
    println!("cargo:rerun-if-changed=src/cpp/mainwindow.h");
}
