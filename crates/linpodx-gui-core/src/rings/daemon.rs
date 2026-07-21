//! Phase 24 — Daemon log ring (Qt-agnostic data layer).
//!
//! Process-wide 200-line ring fed by the connection task via [`push_log_line`].
//! The Qt Daemon tab (Stage 2-C) renders it through [`log_snapshot`]; the
//! render code lives there so this module stays Qt-free and testable.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// Hard cap on the in-memory daemon-log ring.
pub const DAEMON_LOG_CAP: usize = 200;

fn log_ring() -> &'static Mutex<VecDeque<String>> {
    static R: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(VecDeque::with_capacity(DAEMON_LOG_CAP)))
}

/// Append a daemon log line; evicts the oldest past the cap. Safe from any
/// thread; never panics.
pub fn push_log_line(line: String) {
    let Ok(mut guard) = log_ring().lock() else {
        return;
    };
    if guard.len() == DAEMON_LOG_CAP {
        guard.pop_front();
    }
    guard.push_back(line);
}

/// Snapshot a copy of the current log ring.
pub fn log_snapshot() -> Vec<String> {
    log_ring()
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

/// Clear the log ring.
pub fn clear_log() {
    if let Ok(mut guard) = log_ring().lock() {
        guard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_ring_caps_at_200() {
        clear_log();
        for i in 0..(DAEMON_LOG_CAP + 10) {
            push_log_line(format!("line {i}"));
        }
        let snap = log_snapshot();
        assert_eq!(snap.len(), DAEMON_LOG_CAP);
        assert!(snap
            .last()
            .is_some_and(|s| s.ends_with(&format!("line {}", DAEMON_LOG_CAP + 9))));
    }
}
