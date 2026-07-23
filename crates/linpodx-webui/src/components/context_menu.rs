use leptos::ev;
use leptos::prelude::*;

#[derive(Clone)]
pub enum ContextMenuEntry {
    Item(ContextMenuItem),
    Separator,
}

#[derive(Clone)]
pub struct ContextMenuItem {
    pub label: String,
    pub icon: Option<String>,
    pub danger: bool,
    pub disabled: bool,
    pub action: Callback<()>,
}

#[derive(Clone)]
pub struct ContextMenuData {
    x: i32,
    y: i32,
    entries: Vec<ContextMenuEntry>,
}

#[derive(Clone, Copy)]
pub struct ContextMenuState(pub RwSignal<Option<ContextMenuData>>);

impl ContextMenuState {
    pub fn new() -> Self {
        Self(RwSignal::new(None))
    }

    pub fn open(&self, ev: &web_sys::MouseEvent, entries: Vec<ContextMenuEntry>) {
        ev.prevent_default();
        let (x, y) = fit_to_viewport(ev.client_x(), ev.client_y(), &entries);
        self.0.set(Some(ContextMenuData { x, y, entries }));
    }

    pub fn close(&self) {
        self.0.set(None);
    }
}

impl ContextMenuEntry {
    pub fn item(
        label: impl Into<String>,
        icon: Option<&str>,
        danger: bool,
        disabled: bool,
        action: Callback<()>,
    ) -> Self {
        Self::Item(ContextMenuItem {
            label: label.into(),
            icon: icon.map(str::to_string),
            danger,
            disabled,
            action,
        })
    }

    pub fn separator() -> Self {
        Self::Separator
    }
}

#[component]
pub fn ContextMenu(state: ContextMenuState) -> impl IntoView {
    let click_handle = window_event_listener(ev::click, move |_| state.close());
    on_cleanup(move || click_handle.remove());

    let key_handle = window_event_listener(ev::keydown, move |kev: web_sys::KeyboardEvent| {
        if kev.key() == "Escape" {
            state.close();
        }
    });
    on_cleanup(move || key_handle.remove());

    let scroll_handle = window_event_listener(ev::scroll, move |_| state.close());
    on_cleanup(move || scroll_handle.remove());

    view! {
        <Show when=move || state.0.get().is_some() fallback=|| view! { <></> }>
            {move || {
                state.0.get().map(|menu| {
                    let style = format!("left: {}px; top: {}px;", menu.x, menu.y);
                    view! {
                        <div
                            class="context-menu"
                            style=style
                            role="menu"
                            on:click=move |ev| ev.stop_propagation()
                        >
                            {menu.entries.into_iter().map(|entry| {
                                match entry {
                                    ContextMenuEntry::Separator => {
                                        view! { <div class="context-menu__sep" role="separator"></div> }.into_any()
                                    }
                                    ContextMenuEntry::Item(item) => {
                                        let cls = if item.danger {
                                            "context-menu__item context-menu__item--danger"
                                        } else {
                                            "context-menu__item"
                                        };
                                        let disabled = item.disabled;
                                        let action = item.action;
                                        view! {
                                            <button
                                                type="button"
                                                class=cls
                                                role="menuitem"
                                                prop:disabled=disabled
                                                on:click=move |_| {
                                                    if !disabled {
                                                        action.run(());
                                                        state.close();
                                                    }
                                                }
                                            >
                                                {item.icon.map(|icon| view! {
                                                    <span aria-hidden="true">{icon}</span>
                                                })}
                                                <span>{item.label}</span>
                                            </button>
                                        }
                                        .into_any()
                                    }
                                }
                            }).collect_view()}
                        </div>
                    }
                })
            }}
        </Show>
    }
}

pub fn copy_to_clipboard(text: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let win_val: wasm_bindgen::JsValue = win.into();
    let Ok(nav) = js_sys::Reflect::get(&win_val, &wasm_bindgen::JsValue::from_str("navigator"))
    else {
        return;
    };
    let Ok(clip) = js_sys::Reflect::get(&nav, &wasm_bindgen::JsValue::from_str("clipboard")) else {
        return;
    };
    if clip.is_undefined() || clip.is_null() {
        return;
    }
    let Ok(write) = js_sys::Reflect::get(&clip, &wasm_bindgen::JsValue::from_str("writeText"))
    else {
        return;
    };
    if let Ok(func) = wasm_bindgen::JsCast::dyn_into::<js_sys::Function>(write) {
        let _ = func.call1(&clip, &wasm_bindgen::JsValue::from_str(text));
    }
}

pub fn handle_table_key(
    ev: &web_sys::KeyboardEvent,
    keys: Vec<String>,
    focused: RwSignal<Option<String>>,
    blocked: bool,
    primary: impl Fn(String) + Copy,
) {
    if blocked || keys.is_empty() || is_form_field_focused() {
        return;
    }
    match ev.key().as_str() {
        "j" | "ArrowDown" => {
            ev.prevent_default();
            focused.set(Some(next_key(&keys, focused.get_untracked(), 1)));
        }
        "k" | "ArrowUp" => {
            ev.prevent_default();
            focused.set(Some(next_key(&keys, focused.get_untracked(), -1)));
        }
        "Enter" => {
            if let Some(key) = focused.get_untracked().or_else(|| keys.first().cloned()) {
                ev.prevent_default();
                primary(key);
            }
        }
        "Escape" if focused.get_untracked().is_some() => {
            ev.prevent_default();
            focused.set(None);
        }
        _ => {}
    }
}

pub fn focused_row_class(focused: RwSignal<Option<String>>, key: &str) -> &'static str {
    if focused.get().as_deref() == Some(key) {
        "row--focused"
    } else {
        ""
    }
}

fn fit_to_viewport(client_x: i32, client_y: i32, entries: &[ContextMenuEntry]) -> (i32, i32) {
    let width = 220;
    let height = menu_height(entries);
    let (viewport_w, viewport_h) = viewport_size();
    let mut x = if client_x + width > viewport_w {
        client_x - width
    } else {
        client_x
    };
    let mut y = if client_y + height > viewport_h {
        client_y - height
    } else {
        client_y
    };
    x = x.max(8).min((viewport_w - width).max(8));
    y = y.max(8).min((viewport_h - height).max(8));
    (x, y)
}

fn menu_height(entries: &[ContextMenuEntry]) -> i32 {
    let mut height = 8;
    for entry in entries {
        height += match entry {
            ContextMenuEntry::Item(_) => 36,
            ContextMenuEntry::Separator => 8,
        };
    }
    height
}

fn viewport_size() -> (i32, i32) {
    let Some(win) = web_sys::window() else {
        return (1024, 768);
    };
    let w = win
        .inner_width()
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(1024.0) as i32;
    let h = win
        .inner_height()
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(768.0) as i32;
    (w, h)
}

fn next_key(keys: &[String], current: Option<String>, delta: isize) -> String {
    let len = keys.len();
    let current_idx = current
        .and_then(|key| keys.iter().position(|candidate| candidate == &key))
        .unwrap_or(if delta < 0 { len - 1 } else { 0 });
    let next = if delta < 0 {
        current_idx.saturating_sub(1)
    } else {
        (current_idx + 1).min(len - 1)
    };
    keys[next].clone()
}

fn is_form_field_focused() -> bool {
    let Some(active) = web_sys::window()
        .and_then(|win| win.document())
        .and_then(|doc| doc.active_element())
    else {
        return false;
    };
    matches!(
        active.tag_name().to_ascii_lowercase().as_str(),
        "input" | "textarea" | "select"
    )
}
