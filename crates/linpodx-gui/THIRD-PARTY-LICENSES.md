# Third-Party Licenses — linpodx-gui

`linpodx-gui` is a thin **Tauri 2** shell: a single native window whose webview
displays the linpodx daemon's built-in web UI. It bundles no application code of
its own beyond a small splash page.

## WebKitGTK 4.1 (system, dynamically linked)

On Linux, the Tauri webview renders through the system **WebKitGTK 4.1** library
(and its GTK 3 host), which is licensed under the
**GNU Lesser General Public License v2.1 (LGPL-2.1)** (with portions under
BSD-style licenses).

- WebKitGTK is **not** bundled with linpodx; the system-provided shared
  libraries are loaded at runtime. The runtime package name varies by distro:
  - **Debian / Ubuntu:** `libwebkit2gtk-4.1-0`
  - **Fedora:** `webkit2gtk4.1`
  - **openSUSE:** `libwebkit2gtk-4_1-0`
- Dynamic linking satisfies LGPL-2.1 §6: users can replace WebKitGTK by
  installing a different build through their distribution's package manager, and
  linpodx picks it up without relinking.
- WebKitGTK source is available from <https://webkitgtk.org/> and through
  distribution source packages.
- Full license text: <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html>

Build-time development headers (`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev`) are required to compile the shell but are not redistributed.

## Tauri stack (Rust crates)

`tauri`, `tauri-build`, and their supporting crates (wry, tao, and the rest of
the Tauri ecosystem) are licensed **MIT OR Apache-2.0** (Tauri Programme within
The Commons Conservancy). See each crate's repository for the license texts.

## linpodx crates

`linpodx-common` and `linpodx-gui-core` are part of this project (MIT).
