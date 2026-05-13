//! Phase 15 Stream C — pinned WebSocket client certificate store.
//!
//! When the daemon is launched with `--pin-clients`, every TLS handshake whose
//! peer presents a client cert is matched against the `pinned_clients` SQLite
//! table by lowercase-hex SHA-256 of the cert DER. A match accepts the upgrade
//! (audit `WsClientCertPinned`); a miss rejects it with HTTP 403 (audit
//! `RemoteAuthFailed`).
//!
//! The store is intentionally minimal — three columns, no soft-delete, no
//! revocation list. Operators rotate clients by removing the old fingerprint
//! and adding the new one. Future phases can layer signed enrollment or CT-style
//! transparency on top without touching this surface.

use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::PinnedClientSummary;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tracing::warn;

/// Phase 16 Stream C — Trust-On-First-Use mode for client cert pinning.
///
/// When `enabled` is true and the WebSocket upgrade arrives carrying a client
/// cert whose fingerprint is not in [`PinnedClientStore`], the daemon
/// auto-enrolls the fingerprint and accepts the upgrade (instead of rejecting
/// with HTTP 403). Operators get a one-shot bootstrap path without having to
/// pre-distribute fingerprints.
///
/// `max_enrollments` is a defence-in-depth cap — once `current_count` reaches
/// it, TOFU latches off (further mismatches are rejected as before) until an
/// operator explicitly re-enables. `None` means "no cap, until disabled".
///
/// Phase 17 Stream C — adds two time-based fields:
/// * `enabled_at` — Unix-seconds timestamp captured the moment TOFU flipped
///   on, used by [`Self::should_enroll_at`] together with `max_age_secs` to
///   auto-disable after a configured window.
/// * `max_age_secs` — `Some(n)` arms a deadline (`enabled_at + n`); past that
///   point `should_enroll_at(now)` returns `false`. `None` means "no expiry"
///   (Phase 16 semantics retained for callers that never call the new arm).
#[derive(Debug, Clone, Default)]
pub struct TofuMode {
    pub enabled: bool,
    pub max_enrollments: Option<u32>,
    pub current_count: u32,
    /// Unix-seconds timestamp captured the last time `enabled` was flipped
    /// from `false` to `true`. `None` when TOFU has never been enabled, or
    /// when it was enabled before Phase 17's time-tracking landed (the
    /// `*_at` arm refuses to enroll if `max_age_secs` is set but
    /// `enabled_at` is missing, on the conservative side).
    pub enabled_at: Option<i64>,
    /// `Some(secs)` arms the deadline; `None` keeps Phase 16 "expires never"
    /// semantics. Cleared automatically by [`Self::record_expiry`].
    pub max_age_secs: Option<u64>,
}

impl TofuMode {
    /// Construct a freshly-disabled mode with zero auto-enrollments.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_enrollments: None,
            current_count: 0,
            enabled_at: None,
            max_age_secs: None,
        }
    }

    /// Whether a brand-new mismatch should be auto-enrolled. Caller owns the
    /// outer `Mutex`/`Arc`; this method is pure (no I/O, no audit) so the
    /// caller can hold the lock as briefly as possible.
    ///
    /// Phase 17 Stream C — `should_enroll` retains the Phase 16 semantics
    /// (no time-of-day awareness); callers that want expiry enforcement
    /// should call [`Self::should_enroll_at`] with the wall-clock instant
    /// they want to evaluate against (typically `Utc::now().timestamp()`).
    pub fn should_enroll(&self) -> bool {
        if !self.enabled {
            return false;
        }
        match self.max_enrollments {
            Some(max) => self.current_count < max,
            None => true,
        }
    }

    /// Phase 17 Stream C — extended check that consults `max_age_secs`.
    ///
    /// Returns `true` only when:
    /// * `enabled` is true, AND
    /// * the enrolment cap is not yet reached (Phase 16 rule), AND
    /// * either `max_age_secs` is unset, or `now_secs - enabled_at <= max_age_secs`.
    ///
    /// When `max_age_secs` is set but `enabled_at` is `None`, the call
    /// errs on the safe side and returns `false` — TOFU is on but we
    /// have no anchor to measure the window from, which can only happen
    /// after an in-memory state corruption or a hand-crafted test.
    pub fn should_enroll_at(&self, now_secs: i64) -> bool {
        if !self.should_enroll() {
            return false;
        }
        let Some(max_age) = self.max_age_secs else {
            return true;
        };
        let Some(enabled_at) = self.enabled_at else {
            return false;
        };
        // Negative deltas (clock skew or `enabled_at` in the future) count
        // as "no time elapsed yet" — generous toward the operator, since a
        // misconfigured clock should not silently lock people out.
        let elapsed = now_secs.saturating_sub(enabled_at);
        if elapsed < 0 {
            return true;
        }
        (elapsed as u64) <= max_age
    }

    /// Phase 17 Stream C — true when the configured window has elapsed.
    /// Used by the WebSocket handler to decide whether the upcoming
    /// upgrade should also trip an audit + state mutation (one-shot
    /// auto-disable), and by the dispatch IPC arm to surface the same
    /// information through `pin_client_tofu_expiry_status`.
    pub fn is_expired_at(&self, now_secs: i64) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(max_age) = self.max_age_secs else {
            return false;
        };
        let Some(enabled_at) = self.enabled_at else {
            // Same conservative rule as `should_enroll_at`: an anchored
            // window without an anchor is treated as already expired so
            // callers stop enrolling.
            return true;
        };
        let elapsed = now_secs.saturating_sub(enabled_at);
        if elapsed < 0 {
            return false;
        }
        (elapsed as u64) > max_age
    }

    /// Bump the counter. Caller has already verified [`Self::should_enroll_at`] and
    /// committed the fingerprint to the underlying store.
    pub fn record_enrollment(&mut self) {
        self.current_count = self.current_count.saturating_add(1);
    }

    /// Phase 17 Stream C — flip the mode off because the configured window
    /// elapsed. Clears `max_age_secs` so a subsequent operator-driven
    /// `--enable` starts with a fresh budget rather than tripping again on
    /// the same stale deadline. Returns the prior `enabled_at` so the
    /// caller can include it in the audit payload.
    pub fn record_expiry(&mut self) -> Option<i64> {
        let prior = self.enabled_at;
        self.enabled = false;
        self.max_age_secs = None;
        self.enabled_at = None;
        self.current_count = 0;
        prior
    }
}

/// Thread-safe, daemon-lifetime-shared TOFU mode handle. The dispatcher's
/// `DaemonPinClientTofuEnable` arm mutates this, the WebSocket handler reads
/// + mutates it under the same `Mutex` so the enrolment counter never races.
pub type TofuHandle = Arc<Mutex<TofuMode>>;

/// Build a fresh shared handle with TOFU disabled.
pub fn new_tofu_handle() -> TofuHandle {
    Arc::new(Mutex::new(TofuMode::disabled()))
}

/// Compute the lowercase-hex SHA-256 fingerprint of a DER-encoded certificate.
/// This is the value stored in `pinned_clients.fingerprint` and surfaced through
/// the pin-client CLI.
pub fn fingerprint_der(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Convenience for the rustls peer-cert chain — hashes the leaf (first entry).
pub fn fingerprint_rustls_cert(cert: &CertificateDer<'_>) -> String {
    fingerprint_der(cert.as_ref())
}

/// Parse a PEM bundle and return the SHA-256 fingerprint of the first cert.
/// Returns `Error::InvalidArgument` when the PEM contains no certificate.
pub fn fingerprint_from_pem(pem: &[u8]) -> Result<String> {
    let mut reader = std::io::Cursor::new(pem);
    let leaf = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .next()
        .ok_or_else(|| Error::InvalidArgument("no PEM-encoded certificate found".to_string()))?;
    Ok(fingerprint_der(leaf.as_ref()))
}

/// Persisted pin store backed by the daemon's main SQLite handle.
#[derive(Clone)]
pub struct PinnedClientStore {
    db: Arc<Database>,
}

impl PinnedClientStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Insert a new pin. Returns `Ok(false)` when the fingerprint was already
    /// present (no-op upsert) so the caller can surface that to the operator.
    pub async fn insert(&self, fingerprint: &str, label: &str) -> Result<bool> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO pinned_clients (fingerprint, label) VALUES (?1, ?2)",
        )
        .bind(fingerprint)
        .bind(label)
        .execute(self.db.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove a pin by fingerprint. Returns true iff a row was deleted.
    pub async fn remove(&self, fingerprint: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM pinned_clients WHERE fingerprint = ?1")
            .bind(fingerprint)
            .execute(self.db.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Return every pinned client ordered by enrolment time ascending. Cheap
    /// enough — operators won't have thousands of pins, and the table has no
    /// soft-delete column to filter out.
    pub async fn list(&self) -> Result<Vec<PinnedClientSummary>> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT fingerprint, label, enrolled_at FROM pinned_clients ORDER BY enrolled_at ASC",
        )
        .fetch_all(self.db.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (fp, label, enrolled_at) in rows {
            let ts = parse_sqlite_ts(&enrolled_at).unwrap_or_else(chrono::Utc::now);
            out.push(PinnedClientSummary {
                fingerprint: fp,
                label,
                enrolled_at: ts,
            });
        }
        Ok(out)
    }

    /// Constant-time-ish membership check used by the WebSocket upgrade path.
    /// Falls back to `false` (rejection) on any DB error so a momentary outage
    /// doesn't accidentally accept un-pinned clients.
    pub async fn contains(&self, fingerprint: &str) -> bool {
        match sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM pinned_clients WHERE fingerprint = ?1 LIMIT 1",
        )
        .bind(fingerprint)
        .fetch_optional(self.db.pool())
        .await
        {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, fingerprint, "pinned_clients query failed; rejecting by default");
                false
            }
        }
    }

    /// Read a PEM bundle and add the leaf cert's fingerprint as a pin. Returns
    /// the computed fingerprint plus whether the row was newly inserted. The
    /// CLI reads the PEM from disk and forwards the bytes through the IPC
    /// `DaemonPinClientAdd` request — the daemon never sees file paths.
    pub async fn add_from_pem(&self, pem: &[u8], label: &str) -> Result<(String, bool)> {
        let fp = fingerprint_from_pem(pem)?;
        let inserted = self.insert(&fp, label).await?;
        Ok((fp, inserted))
    }
}

fn parse_sqlite_ts(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_self_signed_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["pin-test".into()]).expect("gen");
        cert.cert.pem()
    }

    #[test]
    fn fingerprint_der_is_sha256_lowercase_hex_64chars() {
        let fp = fingerprint_der(b"hello");
        assert_eq!(fp.len(), 64);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known SHA-256 of "hello".
        assert_eq!(
            fp,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn fingerprint_from_pem_extracts_leaf_cert_hash() {
        let pem = make_self_signed_pem();
        let fp = fingerprint_from_pem(pem.as_bytes()).expect("parse");
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn fingerprint_from_pem_rejects_garbage() {
        let err = fingerprint_from_pem(b"not a pem file at all").unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn fingerprint_is_stable_across_pem_reencodes() {
        // Build a cert once, serialise twice (potentially with different newline
        // conventions in the PEM body); the fingerprint hashes the DER, not the
        // PEM, so both round-trips must produce the same digest.
        let cert = rcgen::generate_simple_self_signed(vec!["stable".into()]).expect("gen");
        let pem_a = cert.cert.pem();
        let pem_b = pem_a.replace('\n', "\r\n");
        let fp_a = fingerprint_from_pem(pem_a.as_bytes()).expect("a");
        let fp_b = fingerprint_from_pem(pem_b.as_bytes()).expect("b");
        assert_eq!(fp_a, fp_b);
    }

    async fn open_db() -> Arc<Database> {
        let dir = tempfile::tempdir().expect("tmpdir");
        // tempdir lifetime is bound to a process-static below — shadow with a
        // Box::leak so the Database keeps owning a valid path until the test
        // finishes. The store is in-memory-style cheap; no need to clean up.
        let path = dir.path().join("pin.db");
        Box::leak(Box::new(dir));
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        Arc::new(db)
    }

    #[tokio::test]
    async fn insert_then_contains_then_remove_cycle() {
        let db = open_db().await;
        let store = PinnedClientStore::new(db);
        let fp = "deadbeef".repeat(8);
        assert!(!store.contains(&fp).await);
        assert!(store.insert(&fp, "laptop").await.expect("insert"));
        assert!(store.contains(&fp).await);
        // Re-insert is a no-op upsert.
        assert!(!store.insert(&fp, "laptop").await.expect("re-insert"));
        let listed = store.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].fingerprint, fp);
        assert_eq!(listed[0].label, "laptop");
        // Remove flips it back to absent.
        assert!(store.remove(&fp).await.expect("remove"));
        assert!(!store.contains(&fp).await);
        assert!(!store.remove(&fp).await.expect("second remove"));
    }

    #[tokio::test]
    async fn add_from_pem_persists_leaf_fingerprint() {
        let db = open_db().await;
        let store = PinnedClientStore::new(db);
        let pem = make_self_signed_pem();
        let (fp, inserted) = store.add_from_pem(pem.as_bytes(), "ci").await.expect("add");
        assert!(inserted);
        assert!(store.contains(&fp).await);
        let listed = store.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label, "ci");
    }

    // ----- Phase 16 Stream C — TofuMode -----

    #[test]
    fn tofu_disabled_never_enrolls() {
        let m = TofuMode::disabled();
        assert!(!m.should_enroll());
    }

    #[test]
    fn tofu_enabled_with_no_cap_keeps_enrolling() {
        let mut m = TofuMode {
            enabled: true,
            max_enrollments: None,
            current_count: 0,
            enabled_at: None,
            max_age_secs: None,
        };
        for _ in 0..10 {
            assert!(m.should_enroll(), "should always enroll when uncapped");
            m.record_enrollment();
        }
        assert_eq!(m.current_count, 10);
    }

    #[test]
    fn tofu_enabled_with_cap_latches_off_after_max() {
        let mut m = TofuMode {
            enabled: true,
            max_enrollments: Some(2),
            current_count: 0,
            enabled_at: None,
            max_age_secs: None,
        };
        assert!(m.should_enroll());
        m.record_enrollment();
        assert!(m.should_enroll());
        m.record_enrollment();
        // Hit the cap: should_enroll flips to false until disabled+re-enabled.
        assert!(!m.should_enroll());
        // Even if we keep calling record_enrollment, should_enroll stays false.
        m.record_enrollment();
        assert!(!m.should_enroll());
    }

    #[test]
    fn tofu_record_enrollment_saturates_safely() {
        let mut m = TofuMode {
            enabled: true,
            max_enrollments: None,
            current_count: u32::MAX,
            enabled_at: None,
            max_age_secs: None,
        };
        m.record_enrollment();
        // saturating_add prevents overflow panic.
        assert_eq!(m.current_count, u32::MAX);
    }

    // ----- Phase 17 Stream C — time-based auto-disable -----

    fn enabled_with_window(enabled_at: i64, max_age_secs: u64) -> TofuMode {
        TofuMode {
            enabled: true,
            max_enrollments: None,
            current_count: 0,
            enabled_at: Some(enabled_at),
            max_age_secs: Some(max_age_secs),
        }
    }

    #[test]
    fn tofu_should_enroll_at_when_no_expiry_set_matches_phase16_rule() {
        let m = TofuMode {
            enabled: true,
            max_enrollments: None,
            current_count: 0,
            enabled_at: Some(1_000),
            max_age_secs: None,
        };
        // With no max_age_secs, time-based check returns the same answer as
        // the Phase 16 variant — true regardless of how far in the future
        // `now_secs` lands.
        assert!(m.should_enroll_at(1_000));
        assert!(m.should_enroll_at(1_000 + 86_400 * 365));
        assert!(!m.is_expired_at(1_000 + 86_400 * 365));
    }

    #[test]
    fn tofu_should_enroll_at_window_boundary_inclusive() {
        let m = enabled_with_window(100, 60);
        // Right at the boundary `now - enabled_at == max_age_secs` is still in.
        assert!(m.should_enroll_at(160));
        assert!(!m.is_expired_at(160));
        // One second past the boundary flips it.
        assert!(!m.should_enroll_at(161));
        assert!(m.is_expired_at(161));
    }

    #[test]
    fn tofu_should_enroll_at_clock_skew_negative_delta_grants_enrol() {
        let m = enabled_with_window(1_000, 60);
        // Wall-clock running behind `enabled_at` — treat as no time elapsed.
        assert!(m.should_enroll_at(500));
        assert!(!m.is_expired_at(500));
    }

    #[test]
    fn tofu_should_enroll_at_with_window_but_missing_anchor_refuses() {
        // Defensive: caller forgot to set enabled_at while configuring the
        // window. Refuse to enroll rather than enroll indefinitely.
        let m = TofuMode {
            enabled: true,
            max_enrollments: None,
            current_count: 0,
            enabled_at: None,
            max_age_secs: Some(60),
        };
        assert!(!m.should_enroll_at(0));
        // is_expired_at returns true with the same conservative logic so the
        // dispatch layer can audit the bad state and prompt a re-enable.
        assert!(m.is_expired_at(0));
    }

    #[test]
    fn tofu_disabled_is_never_expired() {
        let m = TofuMode::disabled();
        assert!(!m.is_expired_at(i64::MAX));
        assert!(!m.should_enroll_at(0));
    }

    #[test]
    fn tofu_record_expiry_clears_state_and_returns_prior_anchor() {
        let mut m = enabled_with_window(123, 60);
        m.current_count = 2;
        let prior = m.record_expiry();
        assert_eq!(prior, Some(123));
        assert!(!m.enabled);
        assert!(m.max_age_secs.is_none());
        assert!(m.enabled_at.is_none());
        assert_eq!(m.current_count, 0);
        // After clearing, should_enroll_at refuses regardless of time.
        assert!(!m.should_enroll_at(123));
        assert!(!m.is_expired_at(123));
    }

    #[test]
    fn tofu_should_enroll_at_respects_enrolment_cap_with_window() {
        let mut m = enabled_with_window(0, 1_000);
        m.max_enrollments = Some(1);
        // Within the window + cap not yet hit -> enrol.
        assert!(m.should_enroll_at(10));
        m.record_enrollment();
        // Cap hit: even though window is still open, should_enroll is false.
        assert!(!m.should_enroll_at(10));
        // Same applies via should_enroll (Phase 16 invariant preserved).
        assert!(!m.should_enroll());
    }
}
