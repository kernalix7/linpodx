// Phase 24 — linpodx-gui Qt 6 main window (Stage 1 shell) implementation.
#include "mainwindow.h"

#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QString>
#include <QFrame>
#include <array>

namespace linpodx {

namespace {
// Tab order MUST match state::Tab::ALL (state.rs).
constexpr std::array<const char*, 11> kTabNames = {
    "Containers", "Images", "Volumes", "Networks", "Sandbox",
    "Audit", "Snapshots", "Sessions", "Metrics", "Pinned Clients", "Plugins",
};

QString banner_style(std::int32_t kind) {
    switch (kind) {
        case 1: return QStringLiteral("background:#1e3a5f;color:#cfe3ff;padding:6px;");
        case 2: return QStringLiteral("background:#5f4a1e;color:#ffe9b0;padding:6px;");
        case 3: return QStringLiteral("background:#5f1e1e;color:#ffc0c0;padding:6px;");
        default: return QString();
    }
}
} // namespace

MainWindow::MainWindow() {
    setWindowTitle(QStringLiteral("linpodx"));
    resize(1100, 720);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ---- top banner (hidden until set_banner) ----
    banner_ = new QLabel(central);
    banner_->setVisible(false);
    banner_->setWordWrap(true);
    root->addWidget(banner_);

    // ---- middle: sidebar | stacked pages ----
    auto* mid = new QHBoxLayout();
    mid->setContentsMargins(0, 0, 0, 0);
    mid->setSpacing(0);

    sidebar_ = new QListWidget(central);
    sidebar_->setFixedWidth(200);
    sidebar_->setFrameShape(QFrame::NoFrame);
    sidebar_->setObjectName(QStringLiteral("linpodxSidebar"));

    stack_ = new QStackedWidget(central);

    for (std::size_t i = 0; i < kTabNames.size(); ++i) {
        sidebar_->addItem(QString::fromUtf8(kTabNames[i]));
        // Placeholder page — Stage 2 streams swap in real view widgets via
        // page_at(i)->layout().
        auto* page = new QWidget(stack_);
        auto* pl = new QVBoxLayout(page);
        auto* ph = new QLabel(QStringLiteral("%1 — view pending (Stage 2)")
                                  .arg(QString::fromUtf8(kTabNames[i])),
                              page);
        ph->setAlignment(Qt::AlignCenter);
        pl->addWidget(ph);
        stack_->addWidget(page);
    }

    mid->addWidget(sidebar_);
    mid->addWidget(stack_, 1);

    auto* mid_host = new QWidget(central);
    mid_host->setLayout(mid);
    root->addWidget(mid_host, 1);

    // ---- bottom timeline (50 most-recent events) ----
    timeline_ = new QListWidget(central);
    timeline_->setFixedHeight(96);
    timeline_->setFrameShape(QFrame::NoFrame);
    timeline_->setObjectName(QStringLiteral("linpodxTimeline"));
    root->addWidget(timeline_);

    setCentralWidget(central);

    // Sidebar selection drives the stack. Pure C++ wiring — no Rust round-trip.
    QObject::connect(sidebar_, &QListWidget::currentRowChanged, stack_,
                     &QStackedWidget::setCurrentIndex);
    sidebar_->setCurrentRow(0);
}

QWidget* MainWindow::page_at(std::int32_t index) const {
    if (index < 0 || index >= stack_->count()) {
        return nullptr;
    }
    return stack_->widget(index);
}

void MainWindow::set_banner(rust::Str text, std::int32_t kind) {
    if (kind == 0 || text.empty()) {
        banner_->setVisible(false);
        banner_->clear();
        return;
    }
    banner_->setStyleSheet(banner_style(kind));
    banner_->setText(QString::fromUtf8(text.data(), static_cast<int>(text.size())));
    banner_->setVisible(true);
}

void MainWindow::push_timeline(rust::Str line) {
    timeline_->insertItem(
        0, QString::fromUtf8(line.data(), static_cast<int>(line.size())));
    while (timeline_->count() > 50) {
        delete timeline_->takeItem(timeline_->count() - 1);
    }
}

void MainWindow::set_active_tab(std::int32_t index) {
    if (index >= 0 && index < sidebar_->count()) {
        sidebar_->setCurrentRow(index);
    }
}

std::int32_t MainWindow::active_tab() const {
    return sidebar_->currentRow();
}

// ---- cxx bridge free functions ----
std::unique_ptr<MainWindow> new_main_window() {
    return std::make_unique<MainWindow>();
}
void show_window(MainWindow& w) { w.show(); }
void set_banner(MainWindow& w, rust::Str text, std::int32_t kind) {
    w.set_banner(text, kind);
}
void push_timeline(MainWindow& w, rust::Str line) { w.push_timeline(line); }
void set_active_tab(MainWindow& w, std::int32_t index) { w.set_active_tab(index); }
std::int32_t active_tab(const MainWindow& w) { return w.active_tab(); }

} // namespace linpodx
