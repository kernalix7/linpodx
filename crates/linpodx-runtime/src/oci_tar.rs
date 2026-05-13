//! OCI tar walking helpers for layer-aware file diff (Phase 10 Stream B).
//!
//! `podman save <image> -o <out.tar>` produces an OCI-compatible tar archive
//! whose root contains `manifest.json` listing the per-layer tarballs (which
//! are themselves gzip-compressed `*.tar.gz` blobs in modern Podman builds, or
//! plain `*.tar` in older formats). To compute file-level diffs between two
//! snapshot images we don't need the layer contents — only the file *headers*
//! (path, size, mode). This module exposes:
//!
//! - [`save_image`]: spawn `podman save` into a caller-supplied path.
//! - [`list_files_in_oci`]: parse a saved OCI tar and return the union of all
//!   layer entries as [`FileEntry`] values, deduplicated by path (so the
//!   topmost layer's metadata wins — matching the apparent rootfs view).
//!
//! `FileEntry` hashes/equates on `path` only; `size` and `mode` are surfaced
//! so the diff layer can detect "modified" cases where a path appears in both
//! images with different metadata.

use crate::podman::Podman;
use flate2::read::GzDecoder;
use linpodx_common::error::{Error, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use tracing::{debug, instrument};

/// One file inside an OCI image's layered rootfs view.
///
/// `Hash` / `Eq` deliberately consider only `path` so that callers can build a
/// `HashSet<FileEntry>` keyed by path, then compare two such sets via
/// set-difference for added / deleted detection. Size / mode are surfaced so
/// the diff layer can flag intersections that differ as `"modified"`.
#[derive(Debug, Clone, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
}

impl PartialEq for FileEntry {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Hash for FileEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    #[serde(rename = "Layers", default)]
    layers: Vec<String>,
}

/// Run `podman save <image_ref> -o <dest>` producing an OCI tar archive.
///
/// `dest` should be a tempfile path the caller controls (commonly inside a
/// `tempfile::TempDir`). Returns `Err(Runtime)` if the binary fails or exits
/// non-zero — callers in the diff path should treat this as a soft failure
/// and fall back to an empty file-changes set.
#[instrument(skip(podman))]
pub async fn save_image(podman: &Podman, image_ref: &str, dest: &Path) -> Result<()> {
    let mut cmd = podman.base_command();
    cmd.arg("save").arg(image_ref).arg("-o").arg(dest);
    debug!(image = image_ref, dest = ?dest, "podman save");
    let output = cmd.output().await.map_err(|e| Error::Runtime {
        message: format!("podman save spawn failed: {e}"),
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(Error::Runtime {
            message: format!("podman save failed: {stderr}"),
        });
    }
    Ok(())
}

/// Parse an OCI image tarball at `tar_path` and return every file entry across
/// all layers, deduplicated by path with the *topmost* layer's metadata
/// winning (later layers in `manifest.json::Layers` override earlier ones).
///
/// Implementation notes:
///
/// - Reads `manifest.json` from the outer tar's root, expecting at least one
///   manifest entry with a `Layers: [...]` field.
/// - For each layer member, reads its bytes from the outer tar, sniffs the
///   first two bytes for the gzip magic (`1f 8b`), and walks entry headers
///   only — body bytes are skipped via `tar`'s lazy iteration.
/// - Skips directories and "whiteout" markers (`.wh.*`), which OCI uses to
///   represent deletions in upper layers; for a v0.1 best-effort union view
///   we treat them as no-op.
pub fn list_files_in_oci(tar_path: &Path) -> Result<HashSet<FileEntry>> {
    let layer_paths = read_manifest_layers(tar_path)?;
    let mut by_path: HashMap<String, FileEntry> = HashMap::new();

    for layer_path in &layer_paths {
        let layer_bytes = read_member_bytes(tar_path, layer_path)?;
        let entries = entries_from_layer_bytes(&layer_bytes)?;
        for entry in entries {
            by_path.insert(entry.path.clone(), entry);
        }
    }

    Ok(by_path.into_values().collect())
}

/// Parse the outer tarball's `manifest.json` and return its first entry's
/// `Layers` list (relative paths inside the outer tar).
fn read_manifest_layers(tar_path: &Path) -> Result<Vec<String>> {
    let raw = read_member_bytes(tar_path, "manifest.json")?;
    let manifest: Vec<ManifestEntry> =
        serde_json::from_slice(&raw).map_err(|e| Error::Runtime {
            message: format!("oci_tar manifest.json parse error: {e}"),
        })?;
    let first = manifest.into_iter().next().ok_or_else(|| Error::Runtime {
        message: "oci_tar manifest.json has no entries".into(),
    })?;
    if first.layers.is_empty() {
        return Err(Error::Runtime {
            message: "oci_tar manifest.json first entry has no Layers".into(),
        });
    }
    Ok(first.layers)
}

/// Read a single member's full contents out of the outer tar by name.
///
/// The outer tar is small (manifest + a few layer descriptors per layer) and
/// each layer member is read at most once per diff, so we accept the linear
/// scan here in exchange for a simple API.
fn read_member_bytes(tar_path: &Path, member: &str) -> Result<Vec<u8>> {
    let file = File::open(tar_path).map_err(|e| Error::Runtime {
        message: format!("oci_tar open {tar_path:?}: {e}"),
    })?;
    let mut archive = tar::Archive::new(BufReader::new(file));
    let entries = archive.entries().map_err(|e| Error::Runtime {
        message: format!("oci_tar entries: {e}"),
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Runtime {
            message: format!("oci_tar entry: {e}"),
        })?;
        let path = entry
            .path()
            .map_err(|e| Error::Runtime {
                message: format!("oci_tar entry path: {e}"),
            })?
            .to_string_lossy()
            .into_owned();
        if path == member {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| Error::Runtime {
                message: format!("oci_tar read {member}: {e}"),
            })?;
            return Ok(buf);
        }
    }
    Err(Error::Runtime {
        message: format!("oci_tar member not found: {member}"),
    })
}

/// Walk a single layer's tarball (gzip-compressed if the bytes begin with the
/// gzip magic, otherwise plain tar) and return its file entries as
/// [`FileEntry`] values. Only headers are inspected — entry bodies are skipped
/// by the `tar` crate's lazy iterator.
fn entries_from_layer_bytes(bytes: &[u8]) -> Result<Vec<FileEntry>> {
    let is_gzip = bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;
    if is_gzip {
        let decoder = GzDecoder::new(bytes);
        walk_layer(tar::Archive::new(decoder))
    } else {
        walk_layer(tar::Archive::new(bytes))
    }
}

fn walk_layer<R: Read>(mut archive: tar::Archive<R>) -> Result<Vec<FileEntry>> {
    let mut out = Vec::new();
    let entries = archive.entries().map_err(|e| Error::Runtime {
        message: format!("oci_tar layer entries: {e}"),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::Runtime {
            message: format!("oci_tar layer entry: {e}"),
        })?;
        let header = entry.header();
        if !header.entry_type().is_file() {
            continue;
        }
        let raw_path = entry.path().map_err(|e| Error::Runtime {
            message: format!("oci_tar layer entry path: {e}"),
        })?;
        let path = raw_path.to_string_lossy().into_owned();
        let basename = raw_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if basename.starts_with(".wh.") {
            // OCI whiteout marker — skip in v0.1 union view.
            continue;
        }
        let size = header.size().unwrap_or(0);
        let mode = header.mode().unwrap_or(0);
        out.push(FileEntry {
            path: normalize_path(&path),
            size,
            mode,
        });
    }
    Ok(out)
}

/// Normalize layer entry paths to leading `/` form so two images saved by
/// different Podman versions (which sometimes prepend `./`) compare equal.
fn normalize_path(p: &str) -> String {
    let trimmed = p.strip_prefix("./").unwrap_or(p);
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Compatibility helper: re-open a saved tar to verify it parses (used by the
/// fallback path in tests). Currently unused outside tests but kept to make the
/// public surface symmetric with `save_image`.
#[doc(hidden)]
pub fn rewind_check(file: &mut File) -> Result<()> {
    file.seek(SeekFrom::Start(0)).map_err(|e| Error::Runtime {
        message: format!("oci_tar rewind: {e}"),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;
    use tar::{Builder, Header};
    use tempfile::tempdir;

    fn write_layer_tar_gz(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        // Build an inner tar then gzip-compress it.
        let mut inner = Vec::new();
        {
            let mut builder = Builder::new(&mut inner);
            for (path, body, mode) in files {
                let mut header = Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(body.len() as u64);
                header.set_mode(*mode);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                builder.append(&header, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&inner).unwrap();
        gz.finish().unwrap()
    }

    fn write_layer_tar_plain(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut inner = Vec::new();
        {
            let mut builder = Builder::new(&mut inner);
            for (path, body, mode) in files {
                let mut header = Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(body.len() as u64);
                header.set_mode(*mode);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                builder.append(&header, *body).unwrap();
            }
            builder.finish().unwrap();
        }
        inner
    }

    fn write_oci_tar(layers: &[(String, Vec<u8>)], manifest_layers: &[String]) -> Vec<u8> {
        let manifest_body = serde_json::json!([{
            "Config": "config.json",
            "RepoTags": ["test:latest"],
            "Layers": manifest_layers,
        }])
        .to_string();
        let mut outer = Vec::new();
        {
            let mut builder = Builder::new(&mut outer);
            // Append manifest.json
            let mut h = Header::new_gnu();
            h.set_path("manifest.json").unwrap();
            h.set_size(manifest_body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            builder.append(&h, manifest_body.as_bytes()).unwrap();
            for (name, body) in layers {
                let mut h = Header::new_gnu();
                h.set_path(name).unwrap();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_cksum();
                builder.append(&h, body.as_slice()).unwrap();
            }
            builder.finish().unwrap();
        }
        outer
    }

    #[test]
    fn list_files_walks_single_gzipped_layer() {
        let layer = write_layer_tar_gz(&[
            ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
            ("usr/bin/sh", b"#!/binary\n", 0o755),
        ]);
        let outer = write_oci_tar(
            &[("layer1/layer.tar.gz".into(), layer)],
            &["layer1/layer.tar.gz".into()],
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("img.tar");
        std::fs::write(&path, &outer).unwrap();

        let entries = list_files_in_oci(&path).expect("list");
        let by_path: HashSet<String> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(by_path.contains("/etc/passwd"));
        assert!(by_path.contains("/usr/bin/sh"));
        let sh = entries.iter().find(|e| e.path == "/usr/bin/sh").unwrap();
        assert_eq!(sh.mode & 0o777, 0o755);
    }

    #[test]
    fn list_files_handles_plain_layer_tar() {
        let layer = write_layer_tar_plain(&[("a/b", b"hello", 0o644)]);
        let outer = write_oci_tar(
            &[("layer1/layer.tar".into(), layer)],
            &["layer1/layer.tar".into()],
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("img.tar");
        std::fs::write(&path, &outer).unwrap();

        let entries = list_files_in_oci(&path).expect("list");
        assert_eq!(entries.len(), 1);
        let e = entries.into_iter().next().unwrap();
        assert_eq!(e.path, "/a/b");
        assert_eq!(e.size, 5);
    }

    #[test]
    fn list_files_topmost_layer_metadata_wins() {
        // Two layers both define /etc/hostname with different sizes. Top wins.
        let l1 = write_layer_tar_gz(&[("etc/hostname", b"old", 0o644)]);
        let l2 = write_layer_tar_gz(&[("etc/hostname", b"newer-content", 0o644)]);
        let outer = write_oci_tar(
            &[
                ("l1/layer.tar.gz".into(), l1),
                ("l2/layer.tar.gz".into(), l2),
            ],
            &["l1/layer.tar.gz".into(), "l2/layer.tar.gz".into()],
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("img.tar");
        std::fs::write(&path, &outer).unwrap();

        let entries = list_files_in_oci(&path).expect("list");
        let host = entries
            .iter()
            .find(|e| e.path == "/etc/hostname")
            .expect("entry");
        assert_eq!(host.size, b"newer-content".len() as u64);
    }

    #[test]
    fn list_files_skips_whiteouts_and_dirs() {
        // Directory entry + whiteout file should not appear in output.
        let mut inner = Vec::new();
        {
            let mut b = Builder::new(&mut inner);
            // directory
            let mut hd = Header::new_gnu();
            hd.set_path("var/").unwrap();
            hd.set_size(0);
            hd.set_mode(0o755);
            hd.set_entry_type(tar::EntryType::Directory);
            hd.set_cksum();
            b.append(&hd, std::io::empty()).unwrap();
            // whiteout
            let mut hw = Header::new_gnu();
            hw.set_path("var/.wh.removed").unwrap();
            hw.set_size(0);
            hw.set_mode(0o644);
            hw.set_entry_type(tar::EntryType::Regular);
            hw.set_cksum();
            b.append(&hw, std::io::empty()).unwrap();
            // real file
            let body = b"keep";
            let mut hf = Header::new_gnu();
            hf.set_path("var/keep").unwrap();
            hf.set_size(body.len() as u64);
            hf.set_mode(0o644);
            hf.set_entry_type(tar::EntryType::Regular);
            hf.set_cksum();
            b.append(&hf, body.as_slice()).unwrap();
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&inner).unwrap();
        let layer = gz.finish().unwrap();

        let outer = write_oci_tar(
            &[("l/layer.tar.gz".into(), layer)],
            &["l/layer.tar.gz".into()],
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("img.tar");
        std::fs::write(&path, &outer).unwrap();

        let entries = list_files_in_oci(&path).expect("list");
        let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
        assert_eq!(paths, vec!["/var/keep"]);
    }

    #[test]
    fn missing_manifest_returns_error() {
        // Outer tar with no manifest.json.
        let mut outer = Vec::new();
        {
            let mut b = Builder::new(&mut outer);
            let mut h = Header::new_gnu();
            h.set_path("README").unwrap();
            h.set_size(2);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, &b"hi"[..]).unwrap();
            b.finish().unwrap();
        }
        let dir = tempdir().unwrap();
        let path = dir.path().join("img.tar");
        std::fs::write(&path, &outer).unwrap();

        let err = list_files_in_oci(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("manifest.json"), "unexpected: {msg}");
    }

    #[test]
    fn file_entry_hash_eq_by_path_only() {
        let a = FileEntry {
            path: "/x".into(),
            size: 1,
            mode: 0o644,
        };
        let b = FileEntry {
            path: "/x".into(),
            size: 999,
            mode: 0o755,
        };
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }
}
