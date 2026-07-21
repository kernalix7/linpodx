//! Phase 24 — Events ring (Qt-agnostic data layer).
//!
//! Process-wide 1000-entry ring fed by the state reducer via [`push_event`].
//! The Qt Events tab (Stage 2-C) reads it through [`snapshot`]; the render code
//! lives in that stream, keeping this module free of Qt/UI deps so it stays
//! unit-testable in isolation.

use linpodx_common::ipc::{Event, EventTopic};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// Hard cap on the in-memory ring. Older entries are evicted from the front.
pub const EVENTS_RING_CAP: usize = 1000;

/// Topic filter for the Events tab. `All` matches every topic; the named
/// variants narrow the list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EventFilter {
    #[default]
    All,
    Container,
    Sandbox,
    Snapshot,
    Audit,
}

impl EventFilter {
    pub fn label(self) -> &'static str {
        match self {
            EventFilter::All => "All",
            EventFilter::Container => "Container",
            EventFilter::Sandbox => "Sandbox",
            EventFilter::Snapshot => "Snapshot",
            EventFilter::Audit => "Audit",
        }
    }

    /// True when the event's topic passes the filter.
    pub fn matches(self, topic: EventTopic) -> bool {
        match self {
            EventFilter::All => true,
            EventFilter::Container => matches!(topic, EventTopic::Container),
            EventFilter::Sandbox => matches!(topic, EventTopic::Sandbox),
            EventFilter::Snapshot => matches!(topic, EventTopic::Snapshot),
            EventFilter::Audit => matches!(topic, EventTopic::Audit),
        }
    }
}

fn ring() -> &'static Mutex<VecDeque<Event>> {
    static R: OnceLock<Mutex<VecDeque<Event>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(VecDeque::with_capacity(EVENTS_RING_CAP)))
}

/// Push an event into the GUI's in-memory ring. Called from `App::apply` after
/// the in-place mutations. Safe from any thread; never panics — a poisoned
/// mutex drops the event.
pub fn push_event(event: Event) {
    let Ok(mut guard) = ring().lock() else {
        return;
    };
    if guard.len() == EVENTS_RING_CAP {
        guard.pop_front();
    }
    guard.push_back(event);
}

/// Clear the ring (Events tab "Clear" button).
pub fn clear() {
    if let Ok(mut guard) = ring().lock() {
        guard.clear();
    }
}

/// Snapshot a copy of the current ring. Used by the view and tests.
pub fn snapshot() -> Vec<Event> {
    ring()
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

/// The events ring is a process-wide singleton, so parallel tests that mutate
/// it must serialise. Hand out a static mutex any such test can lock.
#[cfg(test)]
pub(crate) fn ring_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use linpodx_common::ipc::{Event, EventKind, EventTopic};

    fn ev(id: &str) -> Event {
        Event {
            topic: EventTopic::Container,
            kind: EventKind::Created,
            resource_id: id.to_string(),
            timestamp: Utc::now(),
            details: serde_json::json!({ "note": "test" }),
        }
    }

    #[test]
    fn ring_evicts_oldest_past_cap() {
        let _g = ring_test_lock();
        clear();
        for i in 0..(EVENTS_RING_CAP + 50) {
            push_event(ev(&i.to_string()));
        }
        let snap = snapshot();
        assert_eq!(snap.len(), EVENTS_RING_CAP);
        assert_eq!(
            snap.last().unwrap().resource_id,
            (EVENTS_RING_CAP + 49).to_string()
        );
    }

    #[test]
    fn filter_matches_topic() {
        assert!(EventFilter::All.matches(EventTopic::Audit));
        assert!(EventFilter::Container.matches(EventTopic::Container));
        assert!(!EventFilter::Container.matches(EventTopic::Audit));
    }
}
