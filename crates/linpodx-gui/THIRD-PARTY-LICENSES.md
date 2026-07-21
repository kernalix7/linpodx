# Third-Party Licenses — linpodx-gui

## Qt 6

The `linpodx-gui` desktop shell links **dynamically** against the system Qt 6
libraries (QtCore, QtGui, QtWidgets), which are licensed under the
**GNU Lesser General Public License v3.0 (LGPLv3)**.

- Qt is **not** bundled with linpodx; the system-provided shared libraries are
  loaded at runtime (`libQt6Core.so.6`, `libQt6Gui.so.6`, `libQt6Widgets.so.6`).
- Dynamic linking satisfies LGPLv3 §4(d)(1): users can replace the Qt libraries
  by installing a different Qt 6 build through their distribution's package
  manager, and linpodx will pick it up without relinking.
- Qt source code is available from <https://download.qt.io/official_releases/qt/>
  and through distribution source packages.
- Full license text: <https://www.gnu.org/licenses/lgpl-3.0.html>

## Rust bridge crates

`cxx`, `cxx-qt`, `cxx-qt-lib`, `cxx-qt-lib-extras`, and `cxx-qt-build` are
licensed **MIT OR Apache-2.0** (KDAB / dtolnay). See each crate's repository
for the license texts.
