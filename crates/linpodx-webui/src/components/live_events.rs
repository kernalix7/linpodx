//! Live event feed — a real-time stream of daemon events over the `/ipc`
//! WebSocket, rendered as a compact scrolling feed on the dashboard.
//!
//! The daemon pushes JSON-RPC `event` notifications whose `params` is a
//! serialized [`linpodx_common::ipc::Event`]:
//!
//! ```json
//! { "jsonrpc":"2.0", "method":"event",
//!   "params": { "topic":"container", "kind":"started",
//!               "resource_id":"<id>", "timestamp":"2026-…Z", "details":{…} } }
//! ```
//!
//! We open a *single* socket (via [`crate::ws::subscribe_multi`]) subscribed to
//! the container-lifecycle topics and fan every notification into a capped
//! ring buffer (newest first). The pure parsing / classification / ring
//! helpers live at module scope and are unit-tested below; the leptos
//! component is a thin reactive shell over them.
//!
//! UX:
//!   * **pause-on-hover** — while the cursor is over the feed, incoming events
//!     are held in a side buffer so the rows under the pointer don't jump;
//!     they flush (newest first) on mouse-leave.
//!   * **auto-scroll toggle** — when on, the viewport is pinned to the newest
//!     entry (top); when off, your scroll position is preserved so you can read
//!     back through history while new events arrive above.
//!   * **clear** — drops the buffer.
//!   * **deep integration** — an event whose container is currently open in the
//!     detail drawer is highlighted with a subtle accent banner + "in view"
//!     badge, sourced from the shared `DrawerState` context (no cross-file
//!     plumbing — the drawer id already lives in a context provided by
//!     `AppRoot`).

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen::JsCast;
use web_sys::Element;

use crate::app::{AuthToken, DrawerState};
use crate::ws;

/// Ring-buffer capacity — the feed keeps at most this many recent entries.
const RING_CAP: usize = 200;

/// Container-lifecycle topics the feed subscribes to over one socket. Metrics
/// (1 Hz per container) and audit (its own tab) are deliberately excluded to
/// keep the feed high-signal.
const FEED_TOPICS: &[&str] = &[
    "container",
    "image",
    "volume",
    "network",
    "snapshot",
    "sandbox",
    "session",
    "distro",
];

/// A parsed, display-ready feed row. `resource_full` is retained (alongside the
/// truncated `resource_short`) so the component can match against the open
/// drawer's container id.
#[derive(Clone, Debug, PartialEq)]
pub struct FeedEntry {
    /// Monotonic client-assigned id — stable key for the rendered list.
    pub seq: u64,
    /// `HH:MM:SS` extracted from the event's RFC3339 timestamp.
    pub ts: String,
    pub topic: String,
    pub kind: String,
    /// Full resource id (for drawer matching / deep-linking).
    pub resource_full: String,
    /// Truncated resource id for compact display.
    pub resource_short: String,
    /// Best-effort human message pulled from `details` (may be empty).
    pub message: String,
}

/// Map an [`linpodx_common::ipc::EventKind`] string to a status badge class.
/// Semantics: green = came-up / succeeded, red = destroyed / failed, amber =
/// went-down / renamed, blue = informational, grey = unknown.
pub fn kind_badge_class(kind: &str) -> &'static str {
    match kind {
        "started" | "succeeded" | "pulled" => "badge badge--success",
        "created" | "tagged" => "badge badge--info",
        "stopped" | "renamed" => "badge badge--warn",
        "removed" | "failed" => "badge badge--error",
        "progress" | "log" => "badge badge--info",
        _ => "badge badge--neutral",
    }
}

/// Extract `HH:MM:SS` from an RFC3339 timestamp (`2026-07-22T12:34:56.789Z`).
/// Falls back to the raw string when the shape isn't recognised.
pub fn short_time(ts: &str) -> String {
    if let Some(tpos) = ts.find('T') {
        let after = &ts[tpos + 1..];
        let hhmmss: String = after.chars().take(8).collect();
        let b = hhmmss.as_bytes();
        if b.len() == 8 && b[2] == b':' && b[5] == b':' {
            return hhmmss;
        }
    }
    ts.to_string()
}

/// Truncate a long (hex) resource id for compact display.
pub fn short_resource(id: &str) -> String {
    if id.chars().count() > 12 {
        id.chars().take(12).collect()
    } else {
        id.to_string()
    }
}

/// Pull a best-effort human message out of an event's `details` object. Tries a
/// handful of well-known keys the daemon uses across topics; empty when none.
pub fn detail_message(details: &Value) -> String {
    for key in ["message", "line", "name", "ref", "error"] {
        if let Some(s) = details.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// Parse a server-pushed notification into a [`FeedEntry`]. Returns `None` for
/// anything that isn't an `event` notification (e.g. approval frames), so the
/// feed only ever shows lifecycle events.
pub fn parse_event(note: &Value, seq: u64) -> Option<FeedEntry> {
    if note.get("method").and_then(Value::as_str) != Some("event") {
        return None;
    }
    let params = note.get("params")?;
    let topic = params
        .get("topic")
        .and_then(Value::as_str)
        .unwrap_or("event")
        .to_string();
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("event")
        .to_string();
    let resource_full = params
        .get("resource_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let ts_raw = params
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("");
    let message = params
        .get("details")
        .map(detail_message)
        .unwrap_or_default();
    Some(FeedEntry {
        seq,
        ts: short_time(ts_raw),
        topic,
        kind,
        resource_short: short_resource(&resource_full),
        resource_full,
        message,
    })
}

/// Push `entry` to the front of a newest-first ring buffer, dropping the oldest
/// rows once `cap` is exceeded.
pub fn push_capped(buf: &mut Vec<FeedEntry>, entry: FeedEntry, cap: usize) {
    buf.insert(0, entry);
    if buf.len() > cap {
        buf.truncate(cap);
    }
}

#[component]
pub fn LiveEvents() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let drawer = use_context::<DrawerState>().expect("DrawerState context provided by AppRoot");

    // Newest-first ring; `pending` holds events that arrive while paused.
    let entries = RwSignal::new(Vec::<FeedEntry>::new());
    let pending = RwSignal::new(Vec::<FeedEntry>::new());
    let paused = RwSignal::new(false);
    let auto_scroll = RwSignal::new(true);
    let seq = RwSignal::new(0u64);
    let feed_ref = NodeRef::<leptos::html::Div>::new();

    // One socket, many topics. The callback lives as long as the page, so the
    // captured (Copy) signals are always valid. While paused we divert into
    // `pending` so the rows under the cursor stay put.
    ws::subscribe_multi(FEED_TOPICS, move |note| {
        let id = seq.get_untracked();
        seq.set(id.wrapping_add(1));
        let Some(entry) = parse_event(&note, id) else {
            return;
        };
        if paused.get_untracked() {
            pending.update(|p| push_capped(p, entry, RING_CAP));
        } else {
            entries.update(|v| push_capped(v, entry, RING_CAP));
        }
    });

    // Pin the viewport to the newest entry (top) whenever the buffer changes,
    // unless the user has turned auto-scroll off (then we leave scroll alone).
    Effect::new(move |_| {
        let _ = entries.get();
        if !auto_scroll.get_untracked() {
            return;
        }
        if let Some(node) = feed_ref.get() {
            if let Some(el) = (*node).dyn_ref::<Element>() {
                el.set_scroll_top(0);
            }
        }
    });

    let on_enter = move |_| paused.set(true);
    let on_leave = move |_| {
        paused.set(false);
        let mut drained = pending.get_untracked();
        if drained.is_empty() {
            return;
        }
        pending.set(Vec::new());
        // `drained` is already newest-first; splice it ahead of the live buffer.
        entries.update(move |v| {
            drained.append(v);
            *v = std::mem::take(&mut drained);
            if v.len() > RING_CAP {
                v.truncate(RING_CAP);
            }
        });
    };
    let on_clear = move |_| {
        entries.set(Vec::new());
        pending.set(Vec::new());
    };
    let on_toggle_scroll = move |_| auto_scroll.update(|a| *a = !*a);

    let feed_body = move || {
        let items = entries.get();
        if items.is_empty() {
            let hint = if auth.0.get().is_none() {
                "Set a bearer token to stream live daemon events."
            } else {
                "Waiting for daemon events…"
            };
            return view! {
                <div class="empty-state">
                    <div class="empty-state__title">"No events yet"</div>
                    <div class="empty-state__hint">{hint}</div>
                </div>
            }
            .into_any();
        }
        let open = drawer.0.get();
        items
            .into_iter()
            .map(|e| {
                let clickable = e.topic == "container" && !e.resource_full.is_empty();
                let in_drawer = clickable && open.as_deref() == Some(e.resource_full.as_str());
                let badge_cls = kind_badge_class(&e.kind);
                let target = e.resource_full.clone();
                let mut style = String::new();
                if clickable {
                    style.push_str("cursor:pointer;");
                }
                if in_drawer {
                    style.push_str(
                        "border-left:2px solid var(--color-accent);\
                         background:var(--color-accent-soft);padding-left:6px;",
                    );
                }
                let has_msg = !e.message.is_empty();
                view! {
                    <div
                        class="log-line"
                        style=style
                        on:click=move |_| {
                            if clickable {
                                drawer.0.set(Some(target.clone()));
                            }
                        }
                    >
                        <span class="mono">{e.ts}</span>
                        " "
                        <span class=badge_cls>{e.kind}</span>
                        " "
                        <span class="mono">{e.resource_short}</span>
                        {in_drawer
                            .then(|| view! { " "<span class="badge badge--info">"in view"</span> })}
                        {has_msg
                            .then(|| view! { " "<span class="cell-muted">{e.message}</span> })}
                    </div>
                }
            })
            .collect_view()
            .into_any()
    };

    view! {
        <div class="surface-card">
            <div class="toolbar">
                <span class="section-title">"Live events"</span>
                <span class=move || {
                    if paused.get() { "chip chip--warn" } else { "chip chip--success" }
                }>{move || if paused.get() { "paused" } else { "live" }}</span>
                <span class="toolbar__spacer"></span>
                <span class="mono">{move || entries.get().len().to_string()}</span>
                <button type="button" class="btn btn--sm btn--ghost" on:click=on_toggle_scroll>
                    {move || {
                        if auto_scroll.get() { "Auto-scroll: on" } else { "Auto-scroll: off" }
                    }}
                </button>
                <button type="button" class="btn btn--sm btn--secondary" on:click=on_clear>
                    "Clear"
                </button>
            </div>
            <div
                class="log-block"
                node_ref=feed_ref
                on:mouseenter=on_enter
                on:mouseleave=on_leave
            >
                {feed_body}
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(topic: &str, kind: &str, rid: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "event",
            "params": {
                "topic": topic,
                "kind": kind,
                "resource_id": rid,
                "timestamp": "2026-07-22T12:34:56.789Z",
                "details": {}
            }
        })
    }

    #[test]
    fn push_capped_keeps_newest_and_caps() {
        let mut buf = Vec::new();
        for i in 0..250u64 {
            let entry = parse_event(&ev("container", "started", "abc"), i).unwrap();
            push_capped(&mut buf, entry, RING_CAP);
        }
        assert_eq!(buf.len(), RING_CAP);
        // Newest (seq 249) is at the front; oldest surviving is seq 50.
        assert_eq!(buf.first().unwrap().seq, 249);
        assert_eq!(buf.last().unwrap().seq, 250 - RING_CAP as u64);
    }

    #[test]
    fn push_capped_orders_newest_first() {
        let mut buf = Vec::new();
        push_capped(
            &mut buf,
            parse_event(&ev("image", "pulled", "x"), 1).unwrap(),
            10,
        );
        push_capped(
            &mut buf,
            parse_event(&ev("image", "pulled", "y"), 2).unwrap(),
            10,
        );
        assert_eq!(buf[0].seq, 2);
        assert_eq!(buf[1].seq, 1);
    }

    #[test]
    fn parse_event_extracts_fields() {
        let note = ev("container", "started", "deadbeefcafe1234");
        let entry = parse_event(&note, 7).unwrap();
        assert_eq!(entry.seq, 7);
        assert_eq!(entry.topic, "container");
        assert_eq!(entry.kind, "started");
        assert_eq!(entry.resource_full, "deadbeefcafe1234");
        assert_eq!(entry.resource_short, "deadbeefcafe");
        assert_eq!(entry.ts, "12:34:56");
    }

    #[test]
    fn parse_event_rejects_non_event_notifications() {
        let approval = json!({
            "jsonrpc": "2.0",
            "method": "approval_request",
            "params": { "id": "1" }
        });
        assert!(parse_event(&approval, 0).is_none());
    }

    #[test]
    fn parse_event_pulls_detail_message() {
        let note = json!({
            "jsonrpc": "2.0",
            "method": "event",
            "params": {
                "topic": "image",
                "kind": "progress",
                "resource_id": "img1",
                "timestamp": "2026-07-22T00:00:01Z",
                "details": { "message": "downloading layer 3/5" }
            }
        });
        let entry = parse_event(&note, 0).unwrap();
        assert_eq!(entry.message, "downloading layer 3/5");
        assert_eq!(entry.ts, "00:00:01");
    }

    #[test]
    fn kind_classification_covers_semantics() {
        assert_eq!(kind_badge_class("started"), "badge badge--success");
        assert_eq!(kind_badge_class("succeeded"), "badge badge--success");
        assert_eq!(kind_badge_class("created"), "badge badge--info");
        assert_eq!(kind_badge_class("stopped"), "badge badge--warn");
        assert_eq!(kind_badge_class("removed"), "badge badge--error");
        assert_eq!(kind_badge_class("failed"), "badge badge--error");
        assert_eq!(kind_badge_class("renamed"), "badge badge--warn");
        assert_eq!(kind_badge_class("log"), "badge badge--info");
        assert_eq!(
            kind_badge_class("weird-future-kind"),
            "badge badge--neutral"
        );
    }

    #[test]
    fn short_time_falls_back_on_bad_shape() {
        assert_eq!(short_time("not-a-timestamp"), "not-a-timestamp");
        assert_eq!(short_time("2026-07-22T09:08:07.1Z"), "09:08:07");
    }

    #[test]
    fn short_resource_truncates_long_ids() {
        assert_eq!(short_resource("abcdef0123456789"), "abcdef012345");
        assert_eq!(short_resource("short"), "short");
    }

    #[test]
    fn detail_message_prefers_known_keys() {
        assert_eq!(detail_message(&json!({ "line": "hello" })), "hello");
        assert_eq!(detail_message(&json!({ "name": "web" })), "web");
        assert_eq!(detail_message(&json!({})), "");
    }
}
