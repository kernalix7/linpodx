//! On-disk store for the overlayfs snapshot backend.
//!
//! v0.1 does not perform real `overlayfs` mounts; instead it materialises each snapshot's
//! file tree into an `upperdir`-shaped directory under [`store_root()`] and records a
//! sidecar `meta.json`. That layout (lower / upper / work + meta) keeps the on-disk shape
//! compatible with a future real-mount path while letting us deliver commit / tag / size
//! / remove semantics today through plain filesystem operations.
//!
//! Layout (per image_ref):
//! ```text
//! <store_root>/<sha8(image_ref)>/
//!     lower/         empty placeholder (reserved for future stacking)
//!     upper/         materialised content (output of `podman cp <ctr>:/`)
//!     work/          empty placeholder (overlayfs work dir)
//!     meta.json      OverlayMeta — original image, created_at, size, layer_count
//! ```
//!
//! The store root resolves from `LINPODX_OVERLAYFS_ROOT` (used by tests for tempdirs)
//! falling back to `$XDG_DATA_HOME/linpodx/overlayfs` and finally `~/.local/share/linpodx/overlayfs`.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tracing::warn;

const META_FILENAME: &str = "meta.json";
const FUSE_OVERLAYFS_BIN: &str = "fuse-overlayfs";
const FUSERMOUNT_BIN: &str = "fusermount3";

/// Resolve the on-disk root for the overlayfs store. Honours
/// `LINPODX_OVERLAYFS_ROOT` for tests; otherwise picks an XDG-conformant
/// per-user directory.
pub fn store_root() -> PathBuf {
    if let Some(v) = std::env::var_os("LINPODX_OVERLAYFS_ROOT") {
        return PathBuf::from(v);
    }
    let mut p = dirs_local_share();
    p.push("linpodx");
    p.push("overlayfs");
    p
}

/// Per-user data directory: `$XDG_DATA_HOME` or `$HOME/.local/share`. Falls back to `/tmp`
/// when neither is set (last-resort — keeps the helper infallible).
pub fn dirs_local_share() -> PathBuf {
    if let Some(v) = std::env::var_os("XDG_DATA_HOME") {
        let p = PathBuf::from(v);
        if !p.as_os_str().is_empty() {
            return p;
        }
    }
    if let Some(v) = std::env::var_os("HOME") {
        let p = PathBuf::from(v);
        if !p.as_os_str().is_empty() {
            return p.join(".local").join("share");
        }
    }
    PathBuf::from("/tmp")
}

/// Short, stable id derived from an image reference: hex of the first 8 bytes of
/// `sha256(image_ref)` (16 hex chars). Used as the per-image directory name.
pub fn sha8(image_ref: &str) -> String {
    let digest = Sha256::digest(image_ref.as_bytes());
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Root directory for a specific image: `store_root()/<sha8(image_ref)>`.
pub fn image_dir(image_ref: &str) -> PathBuf {
    store_root().join(sha8(image_ref))
}

/// Triple of overlayfs directories plus the parent `root` (the per-image dir).
#[derive(Debug, Clone)]
pub struct LayerDirs {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub root: PathBuf,
}

/// Create `<image_dir>/{lower,upper,work}` (idempotent) and return the resolved paths.
pub fn ensure_dirs(image_ref: &str) -> io::Result<LayerDirs> {
    let root = image_dir(image_ref);
    let lower = root.join("lower");
    let upper = root.join("upper");
    let work = root.join("work");
    fs::create_dir_all(&lower)?;
    fs::create_dir_all(&upper)?;
    fs::create_dir_all(&work)?;
    Ok(LayerDirs {
        lower,
        upper,
        work,
        root,
    })
}

/// Sidecar metadata persisted next to an overlay image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverlayMeta {
    /// The container's source image reference at commit time. Best-effort; may be empty
    /// when the runtime can't resolve it.
    pub original_image: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub layer_count: usize,
}

/// Write `meta` to `<image_dir>/meta.json`. Creates the image dir if missing.
pub fn write_meta(image_ref: &str, meta: &OverlayMeta) -> io::Result<()> {
    let dir = image_dir(image_ref);
    fs::create_dir_all(&dir)?;
    let path = dir.join(META_FILENAME);
    let bytes = serde_json::to_vec_pretty(meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, bytes)
}

/// Read `<image_dir>/meta.json`. Returns `NotFound` when the sidecar is absent.
pub fn read_meta(image_ref: &str) -> io::Result<OverlayMeta> {
    let path = image_dir(image_ref).join(META_FILENAME);
    let raw = fs::read(&path)?;
    serde_json::from_slice::<OverlayMeta>(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Recursively sum the sizes of regular files under `dir`. Symlinks are not followed.
/// Returns 0 for missing directories so call sites can treat "no upper yet" as zero.
pub fn dir_size_bytes(dir: &Path) -> io::Result<u64> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut total: u64 = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let md = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if md.file_type().is_dir() {
            for entry in fs::read_dir(&p)? {
                stack.push(entry?.path());
            }
        } else if md.file_type().is_file() {
            total = total.saturating_add(md.len());
        }
        // Symlinks: contribute 0; we don't follow them.
    }
    Ok(total)
}

// ----- Phase 9 Stream D: real fuse-overlayfs mount + RAII unmount -----

/// Mount-path computation: per-image scratch dir under `/tmp` keyed on the
/// short sha8 of `image_ref`. Stable across process lifetimes — useful so a
/// previous instance's stale dir gets reused/cleaned rather than accumulating
/// `mount-XXXXXX` directories on each commit.
pub fn mount_path(image_ref: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/linpodx-overlay-{}", sha8(image_ref)))
}

/// Reports whether `fuse-overlayfs` is on `PATH`. Cheap (`which` shell-out, no
/// arguments). Tests can shadow this with the `LINPODX_FUSE_OVERLAYFS_AVAILABLE`
/// env override (`"1"` ⇒ available, anything else ⇒ unavailable) so they can
/// exercise both branches without mutating the system PATH.
pub fn fuse_overlayfs_available() -> bool {
    if let Some(v) = std::env::var_os("LINPODX_FUSE_OVERLAYFS_AVAILABLE") {
        return v == "1";
    }
    Command::new("which")
        .arg(FUSE_OVERLAYFS_BIN)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// RAII handle to a fuse-overlayfs mount. Drop runs `fusermount3 -u <mount_path>`
/// best-effort and warns on failure (e.g. the mount was already unmounted by a
/// shutdown handler or the binary is missing). The handle does not delete the
/// mount-point directory itself — the next `mount_layers` call reuses it.
#[derive(Debug)]
pub struct MountedRoot {
    mount_path: PathBuf,
    /// `true` when Drop should actually attempt unmount. Tests bypass it with
    /// [`MountedRoot::for_test_no_unmount`] so they can build/inspect a fake
    /// MountedRoot without invoking `fusermount3` at teardown.
    unmount_on_drop: bool,
}

impl MountedRoot {
    /// Path of the merged overlay root.
    pub fn mount_path(&self) -> &Path {
        &self.mount_path
    }

    /// Construct a MountedRoot whose Drop will NOT shell out to `fusermount3`.
    /// Used by unit tests that want to verify the path round-trip without
    /// assuming the binary is installed.
    #[doc(hidden)]
    pub fn for_test_no_unmount(mount_path: PathBuf) -> Self {
        Self {
            mount_path,
            unmount_on_drop: false,
        }
    }
}

impl Drop for MountedRoot {
    fn drop(&mut self) {
        if !self.unmount_on_drop {
            return;
        }
        let mp = self.mount_path.clone();
        let res = Command::new(FUSERMOUNT_BIN)
            .arg("-u")
            .arg(&mp)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match res {
            Ok(s) if s.success() => {}
            Ok(s) => warn!(path = %mp.display(), status = %s, "fusermount3 -u exited non-zero"),
            Err(e) => warn!(path = %mp.display(), error = %e, "fusermount3 -u spawn failed"),
        }
    }
}

/// Mount the overlay layers for `image_ref` via `fuse-overlayfs`. Returns
/// `Ok(None)` (with a warn) when fuse-overlayfs isn't installed — callers
/// should treat that as "metadata-only commit, no mount available".
///
/// On success, an audit `SnapshotMounted` entry is written through `audit`
/// with payload `{image_ref, mount_path}`, and a `MountedRoot` RAII handle
/// is returned. Dropping the handle runs `fusermount3 -u` (no audit emitted
/// here — the registry that owns the handle is responsible for the
/// `SnapshotUnmounted` audit when it intentionally evicts an entry).
pub async fn mount_layers(
    image_ref: &str,
    audit: Arc<dyn AuditSink>,
) -> io::Result<Option<MountedRoot>> {
    if !fuse_overlayfs_available() {
        warn!(
            image_ref,
            "fuse-overlayfs not available on PATH — skipping mount"
        );
        return Ok(None);
    }
    let dirs = ensure_dirs(image_ref)?;
    let mp = mount_path(image_ref);
    fs::create_dir_all(&mp)?;

    let opt = format!(
        "lowerdir={},upperdir={},workdir={}",
        dirs.lower.display(),
        dirs.upper.display(),
        dirs.work.display()
    );
    let status = Command::new(FUSE_OVERLAYFS_BIN)
        .arg("-o")
        .arg(&opt)
        .arg(&mp)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|e| io::Error::other(format!("fuse-overlayfs spawn: {e}")))?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "fuse-overlayfs exited with status {status}"
        )));
    }
    let payload = serde_json::json!({
        "image_ref": image_ref,
        "mount_path": mp.display().to_string(),
    });
    audit
        .record(AuditSinkKind::SnapshotMounted, None, None, payload)
        .await;
    Ok(Some(MountedRoot {
        mount_path: mp,
        unmount_on_drop: true,
    }))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Cross-test serialisation for `LINPODX_OVERLAYFS_ROOT`. Tests in this crate (in
    //! both `overlayfs::tests` and `snapshot::tests`) mutate a shared env var; without
    //! a process-wide mutex they race when cargo runs them in parallel and read each
    //! other's tempdirs. The guard restores any pre-existing value on drop.

    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn lock() -> &'static Mutex<()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
    }

    pub struct OverlayRootGuard {
        _dir: tempfile::TempDir,
        prev: Option<OsString>,
        // Keep the lock alive for the test body; poison ignored — env restoration is
        // best-effort and the next test will rebuild fresh state anyway.
        _g: MutexGuard<'static, ()>,
    }

    impl OverlayRootGuard {
        pub fn new() -> Self {
            let g = lock().lock().unwrap_or_else(|p| p.into_inner());
            let dir = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var_os("LINPODX_OVERLAYFS_ROOT");
            std::env::set_var("LINPODX_OVERLAYFS_ROOT", dir.path());
            Self {
                _dir: dir,
                prev,
                _g: g,
            }
        }
    }

    impl Drop for OverlayRootGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(p) => std::env::set_var("LINPODX_OVERLAYFS_ROOT", p),
                None => std::env::remove_var("LINPODX_OVERLAYFS_ROOT"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::OverlayRootGuard;
    use super::*;

    #[test]
    fn store_root_honours_env_override() {
        let g = OverlayRootGuard::new();
        // The override is set; verify store_root reads it.
        let from_env = std::env::var_os("LINPODX_OVERLAYFS_ROOT")
            .map(PathBuf::from)
            .expect("env set by guard");
        assert_eq!(store_root(), from_env);
        drop(g);
    }

    #[test]
    fn sha8_is_deterministic_and_short() {
        let a = sha8("alpine:latest");
        let b = sha8("alpine:latest");
        let c = sha8("alpine:edge");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn image_dir_is_deterministic_for_same_ref() {
        let _g = OverlayRootGuard::new();
        let p1 = image_dir("ref-x");
        let p2 = image_dir("ref-x");
        assert_eq!(p1, p2);
    }

    #[test]
    fn ensure_dirs_creates_three_subdirs() {
        let _g = OverlayRootGuard::new();
        let dirs = ensure_dirs("img1").expect("ensure_dirs");
        assert!(dirs.lower.is_dir(), "lower not a dir: {:?}", dirs.lower);
        assert!(dirs.upper.is_dir(), "upper not a dir: {:?}", dirs.upper);
        assert!(dirs.work.is_dir(), "work not a dir: {:?}", dirs.work);
        assert_eq!(dirs.root, image_dir("img1"));
    }

    #[test]
    fn ensure_dirs_is_idempotent() {
        let _g = OverlayRootGuard::new();
        let _a = ensure_dirs("img-idem").expect("first");
        let b = ensure_dirs("img-idem").expect("second");
        assert!(b.upper.is_dir());
    }

    #[test]
    fn write_then_read_meta_round_trip() {
        let _g = OverlayRootGuard::new();
        let meta = OverlayMeta {
            original_image: "alpine:latest".into(),
            created_at: Utc::now(),
            size_bytes: 4096,
            layer_count: 1,
        };
        write_meta("ref-meta", &meta).expect("write");
        let back = read_meta("ref-meta").expect("read");
        assert_eq!(back.original_image, meta.original_image);
        assert_eq!(back.size_bytes, meta.size_bytes);
        assert_eq!(back.layer_count, meta.layer_count);
        // chrono serde preserves nanosecond precision in JSON.
        assert_eq!(back.created_at, meta.created_at);
    }

    #[test]
    fn read_meta_missing_is_not_found() {
        let _g = OverlayRootGuard::new();
        let err = read_meta("never-written").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn dir_size_bytes_sums_regular_files() {
        let _g = OverlayRootGuard::new();
        let dirs = ensure_dirs("img-size").expect("ensure_dirs");
        std::fs::write(dirs.upper.join("a"), b"hello").unwrap();
        std::fs::write(dirs.upper.join("b"), b"world!").unwrap();
        let total = dir_size_bytes(&dirs.upper).expect("size");
        assert_eq!(total, 5 + 6);
    }

    #[test]
    fn dir_size_bytes_missing_dir_is_zero() {
        let _g = OverlayRootGuard::new();
        let p = image_dir("nope").join("upper");
        assert_eq!(dir_size_bytes(&p).unwrap(), 0);
    }

    // ----- Phase 9 Stream D additions -----

    #[test]
    fn mount_path_derives_from_sha8() {
        let p = mount_path("alpine:edge");
        let expected = format!("/tmp/linpodx-overlay-{}", sha8("alpine:edge"));
        assert_eq!(p, std::path::PathBuf::from(expected));
    }

    #[test]
    fn fuse_overlayfs_available_respects_env_override() {
        // We can't safely flip global PATH in a parallel test run; instead the
        // helper honours LINPODX_FUSE_OVERLAYFS_AVAILABLE so we can drive both
        // branches deterministically. Save/restore around the assertions.
        let prev = std::env::var_os("LINPODX_FUSE_OVERLAYFS_AVAILABLE");
        std::env::set_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE", "1");
        assert!(fuse_overlayfs_available());
        std::env::set_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE", "0");
        assert!(!fuse_overlayfs_available());
        match prev {
            Some(v) => std::env::set_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE", v),
            None => std::env::remove_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE"),
        }
    }

    #[tokio::test]
    async fn mount_layers_returns_none_when_fuse_overlayfs_missing() {
        use linpodx_common::audit_sink::NoopAuditSink;
        let _g = OverlayRootGuard::new();
        let prev = std::env::var_os("LINPODX_FUSE_OVERLAYFS_AVAILABLE");
        std::env::set_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE", "0");

        let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let res = mount_layers("img-no-fuse", audit).await.expect("mount");
        assert!(
            res.is_none(),
            "expected None when fuse-overlayfs unavailable"
        );

        match prev {
            Some(v) => std::env::set_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE", v),
            None => std::env::remove_var("LINPODX_FUSE_OVERLAYFS_AVAILABLE"),
        }
    }

    #[test]
    fn mounted_root_for_test_does_not_invoke_fusermount() {
        // Builds a MountedRoot pointing at a path that does NOT exist as a
        // mount; the test-mode constructor must skip Drop's `fusermount3 -u`
        // call so the test passes even if the binary is missing.
        let m =
            MountedRoot::for_test_no_unmount(PathBuf::from("/tmp/linpodx-overlay-doesnotexist"));
        assert_eq!(
            m.mount_path(),
            std::path::Path::new("/tmp/linpodx-overlay-doesnotexist")
        );
        drop(m); // must not panic, must not warn beyond no-op
    }
}
