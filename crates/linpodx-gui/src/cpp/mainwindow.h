// Phase 24 — linpodx-gui Qt 6 main window (Stage 1 shell).
//
// Builds the persistent chrome: a left sidebar (QListWidget, 11 tabs) wired to
// a central QStackedWidget, a top banner QLabel, and a bottom timeline list.
// Stage 2 streams replace each stacked page's placeholder with the real view.
//
// The class is intentionally plain C++ (no Q_OBJECT/moc) for Stage 1: tab
// switching is wired with a lambda connect in the constructor, so no Rust
// round-trip is needed yet. Stage 1.5 introduces a cxx-qt controller QObject
// for state-driven updates.
#pragma once

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QLabel>
#include <memory>
#include <cstdint>

#include "rust/cxx.h"

namespace linpodx {

class MainWindow : public QMainWindow {
public:
    MainWindow();
    ~MainWindow() override = default;

    // Stacked page lookup so Stage 2 streams can mount their view widget into
    // the correct tab index. Returns the page container QWidget*.
    QWidget* page_at(std::int32_t index) const;

    // Banner control (top strip): text + a kind code (0=hidden,1=info,2=warn,3=error).
    void set_banner(rust::Str text, std::int32_t kind);

    // Append one line to the bottom timeline list (most-recent on top, capped).
    void push_timeline(rust::Str line);

    // Programmatic tab switch (mirrors a sidebar click).
    void set_active_tab(std::int32_t index);
    std::int32_t active_tab() const;

private:
    QListWidget* sidebar_ = nullptr;
    QStackedWidget* stack_ = nullptr;
    QLabel* banner_ = nullptr;
    QListWidget* timeline_ = nullptr;
};

// cxx bridge free functions.
std::unique_ptr<MainWindow> new_main_window();
void show_window(MainWindow& w);
void set_banner(MainWindow& w, rust::Str text, std::int32_t kind);
void push_timeline(MainWindow& w, rust::Str line);
void set_active_tab(MainWindow& w, std::int32_t index);
std::int32_t active_tab(const MainWindow& w);

} // namespace linpodx
