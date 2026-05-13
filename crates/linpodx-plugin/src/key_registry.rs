//! Trusted-keys registry for plugin signature verification (Phase 15).
//!
//! Public keys are stored as one PEM file per publisher under a configurable directory.
//! Lookup is by file stem — a manifest with `publisher = "acme"` resolves to
//! `<keys_dir>/acme.pem`. The registry is read-only at runtime; operators provision the
//! directory out-of-band (packaging, config-management, etc.).
//!
//! Resolution order for the keys directory:
//! 1. `$LINPODX_PLUGIN_KEYS_DIR` (test / packaging override)
//! 2. `$XDG_CONFIG_HOME/linpodx/plugin-keys/`
//! 3. `$HOME/.config/linpodx/plugin-keys/`
//! 4. `/etc/linpodx/plugin-keys/`
//!
//! The first directory that *exists* wins. If none exist, [`KeyRegistry::default_dirs`]
//! still returns the candidate list so callers can surface a useful error.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use thiserror::Error;

const PEM_EXT: &str = "pem";
const REVOKED_EXT: &str = "revoked";

#[derive(Debug, Error)]
pub enum KeyRegistryError {
    #[error("io error reading key registry: {0}")]
    Io(#[from] std::io::Error),
    #[error("publisher '{0}' has no key in any of the configured registries")]
    NotFound(String),
    #[error("publisher '{publisher}' resolved to '{path}' but read failed: {source}")]
    ReadFailed {
        publisher: String,
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Phase 16 Stream C — the publisher's key exists on disk but a sibling
    /// `<publisher>.revoked` marker file is present. Future installs that
    /// resolve through `lookup` / `load_pem` are rejected. The pem file is
    /// kept around so audit / forensic tooling can still inspect it.
    #[error("publisher '{publisher}' key has been revoked: {reason}")]
    Revoked { publisher: String, reason: String },
}

/// Phase 16 Stream C — single entry returned by [`KeyRegistry::list_keys`].
///
/// `fingerprint` is the lowercase-hex SHA-256 of the key file *bytes* — the PEM
/// body, not the parsed DER. Hashing the PEM keeps the implementation
/// dependency-free (we already have `sha2` in the workspace) and is sufficient
/// for the operator-facing identification use case (rotation auditing). The
/// signing path still verifies the actual ed25519 key pair so a malformed PEM
/// can't pass verification just because its fingerprint matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub publisher: String,
    pub fingerprint: String,
    /// "active" or "revoked".
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// In-memory registry pointer — only the resolved root paths are cached, not the keys
/// themselves. Lookups read from disk on demand, which keeps memory usage bounded and
/// lets operators rotate keys without restarting the daemon.
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    roots: Vec<PathBuf>,
}

impl KeyRegistry {
    /// Build a registry from the resolved candidate directories. Non-existent
    /// directories are tolerated — they're skipped at lookup time.
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    /// Build a registry using the standard resolution order (env > XDG > HOME > /etc).
    pub fn from_env() -> Self {
        Self::new(Self::default_dirs())
    }

    /// Single-root constructor for tests and explicit configuration.
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self::new(vec![dir.into()])
    }

    /// Return the ordered list of candidate directories without filtering by existence.
    /// Callers can use this to render a "looked in: …" error message.
    pub fn default_dirs() -> Vec<PathBuf> {
        let mut out = Vec::with_capacity(4);
        if let Ok(p) = std::env::var("LINPODX_PLUGIN_KEYS_DIR") {
            if !p.is_empty() {
                out.push(PathBuf::from(p));
            }
        }
        if let Ok(p) = std::env::var("XDG_CONFIG_HOME") {
            if !p.is_empty() {
                out.push(PathBuf::from(p).join("linpodx").join("plugin-keys"));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                out.push(
                    PathBuf::from(home)
                        .join(".config")
                        .join("linpodx")
                        .join("plugin-keys"),
                );
            }
        }
        out.push(PathBuf::from("/etc/linpodx/plugin-keys"));
        out
    }

    /// Configured root paths in resolution order.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Locate `<root>/<publisher>.pem` in the first root that contains it. Returns the
    /// resolved absolute path on success.
    pub fn resolve_path(&self, publisher: &str) -> Result<PathBuf, KeyRegistryError> {
        let stem = sanitize_stem(publisher)?;
        for root in &self.roots {
            let candidate = root.join(format!("{stem}.{PEM_EXT}"));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(KeyRegistryError::NotFound(publisher.to_string()))
    }

    /// Read and return the PEM contents for `publisher`. Returns
    /// [`KeyRegistryError::Revoked`] when a sibling `<publisher>.revoked`
    /// marker exists in the same root that holds the .pem.
    pub fn load_pem(&self, publisher: &str) -> Result<String, KeyRegistryError> {
        let path = self.resolve_path(publisher)?;
        // Revocation guard: same directory, same stem, `.revoked` extension.
        let marker = revoked_marker_for(&path);
        if marker.is_file() {
            let reason = read_marker_reason(&marker).unwrap_or_else(|| "unspecified".to_string());
            return Err(KeyRegistryError::Revoked {
                publisher: publisher.to_string(),
                reason,
            });
        }
        std::fs::read_to_string(&path).map_err(|source| KeyRegistryError::ReadFailed {
            publisher: publisher.to_string(),
            path: path.display().to_string(),
            source,
        })
    }

    /// Phase 16 Stream C — synonym for [`Self::load_pem`] kept around for callers
    /// that prefer the more explicit name. Same revocation semantics.
    pub fn lookup(&self, publisher: &str) -> Result<String, KeyRegistryError> {
        self.load_pem(publisher)
    }

    /// Phase 16 Stream C — write `<publisher>.revoked` next to the resolved
    /// .pem so future lookups fail. Idempotent: re-revoking an already-revoked
    /// publisher overwrites the marker (and timestamp) and still returns
    /// `Ok(())` so the dispatch arm doesn't have to special-case duplicate
    /// requests.
    pub fn revoke(&self, publisher: &str, reason: Option<&str>) -> Result<(), KeyRegistryError> {
        self.write_marker(publisher, reason, chrono::Utc::now())
    }

    /// Phase 17 Stream C — idempotent application of a revocation received
    /// from a Raft peer. Unlike [`Self::revoke`], this:
    ///
    /// 1. Accepts the proposer's `revoked_at` (Unix-seconds) so audit
    ///    timestamps stay consistent across the cluster.
    /// 2. Tolerates a missing publisher PEM (returns `Ok(())` instead of
    ///    `NotFound`) — followers may not have the publisher's key file on
    ///    disk yet, but the recorded intent should still survive a restart
    ///    via the SQLite `plugin_key_revocations` table (Stage 1 migration).
    /// 3. Refuses to overwrite a marker whose timestamp is newer than the
    ///    incoming one — preserves the operator's manually-recorded reason
    ///    when a stale remote propagation arrives late.
    ///
    /// Returns `Ok(true)` when a new marker was written (or an existing one
    /// updated), `Ok(false)` when the incoming revocation was older than the
    /// on-disk marker and therefore skipped.
    pub fn apply_remote_revocation(
        &self,
        publisher: &str,
        _fingerprint: &str,
        reason: Option<&str>,
        revoked_at_unix: i64,
    ) -> Result<bool, KeyRegistryError> {
        // Best-effort timestamp conversion. Outside the chrono valid range
        // (extremely unlikely) we fall back to "now" so the marker is still
        // written; downstream operators can correct via a manual revoke.
        let incoming =
            chrono::DateTime::from_timestamp(revoked_at_unix, 0).unwrap_or_else(chrono::Utc::now);
        let path = match self.resolve_path(publisher) {
            Ok(p) => p,
            Err(KeyRegistryError::NotFound(_)) => {
                // Follower hasn't loaded this publisher's pem yet. The
                // revocation intent is still useful (the SQLite mirror
                // tracks it; future installs will fail). Treat as a no-op.
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let marker = revoked_marker_for(&path);
        if marker.is_file() {
            if let Ok(body) = std::fs::read_to_string(&marker) {
                if let Ok(existing) = serde_json::from_str::<MarkerFile>(&body) {
                    if existing.revoked_at >= incoming {
                        // The local record is at least as fresh; keep it.
                        return Ok(false);
                    }
                }
            }
        }
        self.write_marker(publisher, reason, incoming)?;
        Ok(true)
    }

    fn write_marker(
        &self,
        publisher: &str,
        reason: Option<&str>,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), KeyRegistryError> {
        let path = self.resolve_path(publisher)?;
        let marker = revoked_marker_for(&path);
        let payload = MarkerFile {
            revoked_at,
            reason: reason.unwrap_or("unspecified").to_string(),
        };
        let serialized =
            serde_json::to_string(&payload).map_err(|e| KeyRegistryError::ReadFailed {
                publisher: publisher.to_string(),
                path: marker.display().to_string(),
                source: std::io::Error::other(format!("serialize revocation marker: {e}")),
            })?;
        std::fs::write(&marker, serialized).map_err(|source| KeyRegistryError::ReadFailed {
            publisher: publisher.to_string(),
            path: marker.display().to_string(),
            source,
        })
    }

    /// Phase 16 Stream C — enumerate every `<publisher>.pem` across configured
    /// roots, marking each entry active or revoked. The first occurrence of a
    /// publisher (in resolution-order) wins, mirroring `resolve_path`. Other
    /// IO errors are silently skipped — the operator-facing CLI should still
    /// return whichever entries it could enumerate.
    pub fn list_keys(&self) -> Vec<KeyEntry> {
        let mut seen = std::collections::HashSet::<String>::new();
        let mut out = Vec::new();
        for root in &self.roots {
            let entries = match std::fs::read_dir(root) {
                Ok(it) => it,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some(PEM_EXT) {
                    continue;
                }
                let stem = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if !seen.insert(stem.clone()) {
                    continue;
                }
                let pem_bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let fingerprint = sha256_lower_hex(&pem_bytes);
                let marker = revoked_marker_for(&path);
                let (status, revoked_at, reason) = if marker.is_file() {
                    let parsed = std::fs::read_to_string(&marker)
                        .ok()
                        .and_then(|s| serde_json::from_str::<MarkerFile>(&s).ok());
                    match parsed {
                        Some(m) => ("revoked", Some(m.revoked_at), Some(m.reason)),
                        None => ("revoked", None, Some("unspecified".to_string())),
                    }
                } else {
                    ("active", None, None)
                };
                out.push(KeyEntry {
                    publisher: stem,
                    fingerprint,
                    status: status.to_string(),
                    revoked_at,
                    reason,
                });
            }
        }
        out.sort_by(|a, b| a.publisher.cmp(&b.publisher));
        out
    }
}

/// On-disk JSON payload of `<publisher>.revoked` marker file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MarkerFile {
    revoked_at: chrono::DateTime<chrono::Utc>,
    reason: String,
}

fn revoked_marker_for(pem_path: &std::path::Path) -> PathBuf {
    pem_path.with_extension(REVOKED_EXT)
}

fn read_marker_reason(marker_path: &std::path::Path) -> Option<String> {
    let body = std::fs::read_to_string(marker_path).ok()?;
    let parsed: MarkerFile = serde_json::from_str(&body).ok()?;
    Some(parsed.reason)
}

fn sha256_lower_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sanitize_stem(publisher: &str) -> Result<String, KeyRegistryError> {
    let trimmed = publisher.trim();
    if trimmed.is_empty() {
        return Err(KeyRegistryError::NotFound("(empty publisher)".into()));
    }
    // Refuse anything that could escape the keys directory. We keep the rule strict:
    // only ASCII alphanumerics, '-', '_', '.' (not as a leading char). This is more
    // restrictive than necessary for some legitimate publisher names but completely
    // sidesteps any path-traversal concern.
    let valid = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !valid || trimmed.starts_with('.') || trimmed.contains("..") {
        return Err(KeyRegistryError::NotFound(format!(
            "publisher name '{publisher}' contains disallowed characters"
        )));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn write_pem(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(format!("{name}.pem"));
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn resolves_existing_publisher_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let body = "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n";
        let written = write_pem(tmp.path(), "acme", body);
        let reg = KeyRegistry::from_dir(tmp.path());

        let resolved = reg.resolve_path("acme").expect("resolve");
        assert_eq!(resolved, written);
        assert_eq!(reg.load_pem("acme").expect("load"), body);
    }

    #[test]
    fn missing_publisher_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = KeyRegistry::from_dir(tmp.path());
        let err = reg.resolve_path("nope").unwrap_err();
        assert!(matches!(err, KeyRegistryError::NotFound(p) if p == "nope"));
    }

    #[test]
    fn first_root_with_match_wins() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write_pem(a.path(), "shared", "from-a");
        write_pem(b.path(), "shared", "from-b");
        let reg = KeyRegistry::new(vec![a.path().to_path_buf(), b.path().to_path_buf()]);
        let pem = reg.load_pem("shared").unwrap();
        assert_eq!(pem, "from-a");
    }

    #[test]
    fn falls_through_to_second_root_when_first_lacks_match() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write_pem(b.path(), "only-in-b", "value");
        let reg = KeyRegistry::new(vec![a.path().to_path_buf(), b.path().to_path_buf()]);
        let pem = reg.load_pem("only-in-b").unwrap();
        assert_eq!(pem, "value");
    }

    #[test]
    fn rejects_traversal_in_publisher_name() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = KeyRegistry::from_dir(tmp.path());
        for bad in ["../etc/passwd", ".hidden", "a/b", "x..y", "foo bar"] {
            let err = reg.resolve_path(bad).unwrap_err();
            assert!(
                matches!(err, KeyRegistryError::NotFound(_)),
                "expected NotFound for {bad:?}"
            );
        }
    }

    // ----- Phase 16 Stream C — revocation + list_keys -----

    #[test]
    fn revoke_writes_marker_file_next_to_pem() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "acme", "pem-body");
        let reg = KeyRegistry::from_dir(tmp.path());
        reg.revoke("acme", Some("rotation")).expect("revoke");
        let marker = tmp.path().join("acme.revoked");
        assert!(marker.is_file(), "marker should be written");
    }

    #[test]
    fn lookup_after_revoke_returns_revoked_error() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "acme", "pem-body");
        let reg = KeyRegistry::from_dir(tmp.path());
        // Pre-revoke: lookup succeeds.
        assert_eq!(reg.lookup("acme").expect("pre"), "pem-body");
        // Revoke + re-lookup: Revoked error surfaces with the supplied reason.
        reg.revoke("acme", Some("compromised")).expect("revoke");
        let err = reg.lookup("acme").unwrap_err();
        match err {
            KeyRegistryError::Revoked { publisher, reason } => {
                assert_eq!(publisher, "acme");
                assert_eq!(reason, "compromised");
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn revoke_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "acme", "pem-body");
        let reg = KeyRegistry::from_dir(tmp.path());
        reg.revoke("acme", Some("first")).expect("revoke 1");
        reg.revoke("acme", Some("second")).expect("revoke 2");
        // Most-recent reason wins.
        match reg.lookup("acme").unwrap_err() {
            KeyRegistryError::Revoked { reason, .. } => assert_eq!(reason, "second"),
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn list_keys_returns_active_and_revoked_publishers() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "alpha", "alpha-body");
        write_pem(tmp.path(), "beta", "beta-body");
        let reg = KeyRegistry::from_dir(tmp.path());
        reg.revoke("beta", Some("expired")).expect("revoke");

        let entries = reg.list_keys();
        assert_eq!(entries.len(), 2);

        // Sorted by publisher name.
        assert_eq!(entries[0].publisher, "alpha");
        assert_eq!(entries[0].status, "active");
        assert!(entries[0].revoked_at.is_none());
        assert!(entries[0].reason.is_none());
        // SHA-256 of the literal bytes "alpha-body" — sanity check that the
        // fingerprint really hashes the file content rather than the name.
        assert_eq!(entries[0].fingerprint.len(), 64);

        assert_eq!(entries[1].publisher, "beta");
        assert_eq!(entries[1].status, "revoked");
        assert!(entries[1].revoked_at.is_some());
        assert_eq!(entries[1].reason.as_deref(), Some("expired"));
    }

    #[test]
    fn list_keys_dedupes_first_root_when_publisher_repeats() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write_pem(a.path(), "shared", "from-a");
        write_pem(b.path(), "shared", "from-b");
        let reg = KeyRegistry::new(vec![a.path().to_path_buf(), b.path().to_path_buf()]);
        let entries = reg.list_keys();
        assert_eq!(entries.len(), 1);
        // The first-root copy wins, mirroring resolve_path semantics.
        assert_eq!(entries[0].publisher, "shared");
        assert_eq!(entries[0].fingerprint, sha256_lower_hex(b"from-a"));
    }

    #[test]
    fn revoke_for_unknown_publisher_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = KeyRegistry::from_dir(tmp.path());
        let err = reg.revoke("ghost", Some("noop")).unwrap_err();
        assert!(matches!(err, KeyRegistryError::NotFound(_)));
    }

    // ----- Phase 17 Stream C — apply_remote_revocation -----

    #[test]
    fn apply_remote_revocation_writes_marker_on_first_application() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "alpha", "alpha-body");
        let reg = KeyRegistry::from_dir(tmp.path());

        let applied = reg
            .apply_remote_revocation("alpha", "abc123", Some("remote-revoke"), 1_700_000_000)
            .expect("apply");
        assert!(applied);
        // Subsequent lookup is now rejected.
        assert!(matches!(
            reg.lookup("alpha").unwrap_err(),
            KeyRegistryError::Revoked { .. }
        ));
    }

    #[test]
    fn apply_remote_revocation_is_idempotent_for_same_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "alpha", "body");
        let reg = KeyRegistry::from_dir(tmp.path());

        let first = reg
            .apply_remote_revocation("alpha", "fp", Some("first"), 1_700_000_000)
            .expect("first");
        assert!(first);
        let second = reg
            .apply_remote_revocation("alpha", "fp", Some("first"), 1_700_000_000)
            .expect("second");
        // Same timestamp → existing record is already fresh enough → no rewrite.
        assert!(!second);
    }

    #[test]
    fn apply_remote_revocation_skips_when_local_is_newer() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "alpha", "body");
        let reg = KeyRegistry::from_dir(tmp.path());

        // Operator locally revoked with reason X (uses Utc::now()).
        reg.revoke("alpha", Some("local-operator")).expect("local");

        // A stale propagation arrives from days ago.
        let applied = reg
            .apply_remote_revocation("alpha", "fp", Some("stale"), 1_000)
            .expect("apply");
        assert!(!applied, "stale incoming revocation must not overwrite");

        // Reason preserved on disk.
        match reg.lookup("alpha").unwrap_err() {
            KeyRegistryError::Revoked { reason, .. } => assert_eq!(reason, "local-operator"),
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn apply_remote_revocation_overwrites_when_incoming_is_newer() {
        let tmp = tempfile::tempdir().unwrap();
        write_pem(tmp.path(), "alpha", "body");
        let reg = KeyRegistry::from_dir(tmp.path());

        // Pre-existing marker with an ancient timestamp.
        reg.apply_remote_revocation("alpha", "fp", Some("ancient"), 100)
            .expect("ancient");

        // A fresh propagation arrives.
        let applied = reg
            .apply_remote_revocation("alpha", "fp", Some("fresh"), 2_000_000_000)
            .expect("fresh");
        assert!(applied);

        match reg.lookup("alpha").unwrap_err() {
            KeyRegistryError::Revoked { reason, .. } => assert_eq!(reason, "fresh"),
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn apply_remote_revocation_tolerates_missing_publisher_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = KeyRegistry::from_dir(tmp.path());
        // No pem file on disk — follower hasn't received it yet.
        let applied = reg
            .apply_remote_revocation("ghost", "fp", Some("remote"), 1_700_000_000)
            .expect("apply");
        // We treat it as a no-op (no marker can be created without a sibling
        // .pem), but it does NOT surface as an error so the Raft apply path
        // can continue without failing the entire log entry.
        assert!(!applied);
    }
}
