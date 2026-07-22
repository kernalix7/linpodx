//! System-level aggregate dispatch handlers (Phase 25).
//!
//! [`Dispatcher::system_df`] powers `GET /api/v1/system/df`. It always produces
//! counts (and an image-size sum) from the container/image/volume list
//! surfaces so the endpoint works whenever podman is reachable. It then makes a
//! best-effort `podman system df --format json` call to overlay accurate
//! size / reclaimable figures, silently falling back to the list-derived
//! numbers when podman's output is missing or in an unexpected shape.

use super::*;
use linpodx_common::ipc::responses::{
    SystemDfContainers, SystemDfImages, SystemDfResponse, SystemDfVolumes,
};
use linpodx_common::state::{ContainerState, ContainerSummary, ImageSummary};
use tokio::process::Command;

impl Dispatcher {
    pub(crate) async fn system_df(&self) -> Result<serde_json::Value> {
        // Counts always come from the list surfaces. If even these fail
        // (podman entirely unavailable), surface UNAVAILABLE (-32008) per the
        // API contract.
        let containers =
            self.podman.list(true).await.map_err(|e| {
                Error::Unavailable(format!("system df: container list failed: {e}"))
            })?;
        let images = image::list(
            &self.podman,
            &linpodx_common::ipc::ImageListParams::default(),
        )
        .await
        .map_err(|e| Error::Unavailable(format!("system df: image list failed: {e}")))?;
        let volumes = volume::list(&self.podman)
            .await
            .map_err(|e| Error::Unavailable(format!("system df: volume list failed: {e}")))?;

        let mut resp = build_system_df_from_lists(&containers, &images, volumes.len());

        // Best-effort accuracy pass. Any spawn/exit/parse/shape failure leaves
        // the list-derived numbers untouched.
        if let Some(entries) = self.query_podman_df().await {
            apply_podman_df(&mut resp, &entries);
        }

        Ok(serde_json::to_value(resp)?)
    }

    /// Run `podman system df --format json` and return the raw JSON array.
    /// Returns `None` on any spawn / non-zero-exit / parse failure so the
    /// caller can keep the list-derived figures.
    async fn query_podman_df(&self) -> Option<Vec<serde_json::Value>> {
        let out = Command::new(&self.podman_bin)
            .args(["system", "df", "--format", "json"])
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            warn!(
                status = out.status.code().unwrap_or(-1),
                "podman system df exited non-zero; using list-derived sizes"
            );
            return None;
        }
        match serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
            Ok(entries) => Some(entries),
            Err(e) => {
                warn!(error = %e, "podman system df JSON parse failed; using list-derived sizes");
                None
            }
        }
    }
}

/// Build the list-only view of disk usage: counts + running tally + image-size
/// sum. Container/volume sizes and image reclaimable are left `None` — only
/// `podman system df` can produce those accurately. Pure + synchronous so it is
/// unit-testable without podman.
pub(crate) fn build_system_df_from_lists(
    containers: &[ContainerSummary],
    images: &[ImageSummary],
    volume_count: usize,
) -> SystemDfResponse {
    let running = containers
        .iter()
        .filter(|c| matches!(c.state, ContainerState::Running))
        .count() as u64;
    // NOTE: summing per-image sizes double-counts shared layers; this is the
    // sanctioned first-cut approximation until `podman system df` overrides it.
    let image_size: u64 = images.iter().map(|i| i.size_bytes).sum();
    SystemDfResponse {
        containers: SystemDfContainers {
            total: containers.len() as u64,
            running,
            size_bytes: None,
        },
        images: SystemDfImages {
            total: images.len() as u64,
            size_bytes: Some(image_size),
            reclaimable_bytes: None,
        },
        volumes: SystemDfVolumes {
            total: volume_count as u64,
            size_bytes: None,
        },
        build_cache_bytes: None,
    }
}

/// Overlay accurate size / reclaimable figures parsed from `podman system df
/// --format json` onto a list-derived response. Only numeric fields override;
/// unknown entry types and non-numeric values are ignored so an unexpected
/// podman output shape can never corrupt the response.
fn apply_podman_df(resp: &mut SystemDfResponse, entries: &[serde_json::Value]) {
    for entry in entries {
        let kind = entry
            .get("Type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        // Podman 5.x `system df --format json` emits `RawSize` / `RawReclaimable`
        // as integer bytes while `Size` / `Reclaimable` are human strings
        // (`"56.44GB"`, `"45.45GB (81%)"`). Prefer the raw integer fields; fall
        // back to `Size` / `Reclaimable` only when they are themselves integers
        // (older shapes), never guessing from a human string.
        let size = entry
            .get("RawSize")
            .and_then(value_u64)
            .or_else(|| entry.get("Size").and_then(value_u64));
        let reclaimable = entry
            .get("RawReclaimable")
            .and_then(value_u64)
            .or_else(|| entry.get("Reclaimable").and_then(value_u64));
        if kind.contains("image") {
            if let Some(s) = size {
                resp.images.size_bytes = Some(s);
            }
            if let Some(r) = reclaimable {
                resp.images.reclaimable_bytes = Some(r);
            }
        } else if kind.contains("container") {
            if let Some(s) = size {
                resp.containers.size_bytes = Some(s);
            }
        } else if kind.contains("volume") {
            if let Some(s) = size {
                resp.volumes.size_bytes = Some(s);
            }
        }
    }
}

/// Extract a `u64` from a JSON value only when it is an integer number.
/// Human-formatted strings (e.g. `"1.2GB"`) return `None` so we never guess.
fn value_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use linpodx_common::types::{ContainerId, ImageId};

    fn container(state: ContainerState) -> ContainerSummary {
        ContainerSummary {
            id: ContainerId::new("c"),
            names: vec![],
            image: "alpine".into(),
            state,
            status: String::new(),
            created: Utc::now(),
            command: None,
            ports: vec![],
        }
    }

    fn image(size: u64) -> ImageSummary {
        ImageSummary {
            id: ImageId::new("i"),
            repo_tags: vec![],
            repo_digests: vec![],
            size_bytes: size,
            created: Utc::now(),
            labels: Default::default(),
        }
    }

    #[test]
    fn build_counts_running_and_sums_image_sizes() {
        let containers = vec![
            container(ContainerState::Running),
            container(ContainerState::Exited),
            container(ContainerState::Running),
        ];
        let images = vec![image(100), image(250)];
        let df = build_system_df_from_lists(&containers, &images, 4);

        assert_eq!(df.containers.total, 3);
        assert_eq!(df.containers.running, 2);
        assert_eq!(df.containers.size_bytes, None);
        assert_eq!(df.images.total, 2);
        assert_eq!(df.images.size_bytes, Some(350));
        assert_eq!(df.images.reclaimable_bytes, None);
        assert_eq!(df.volumes.total, 4);
        assert_eq!(df.volumes.size_bytes, None);
        assert_eq!(df.build_cache_bytes, None);
    }

    #[test]
    fn build_empty_lists_yield_zeros() {
        let df = build_system_df_from_lists(&[], &[], 0);
        assert_eq!(df.containers.total, 0);
        assert_eq!(df.containers.running, 0);
        assert_eq!(df.images.total, 0);
        assert_eq!(df.images.size_bytes, Some(0));
        assert_eq!(df.volumes.total, 0);
    }

    #[test]
    fn apply_df_overrides_numeric_sizes() {
        let mut df = build_system_df_from_lists(&[], &[image(1)], 0);
        let entries = serde_json::json!([
            { "Type": "Images", "Total": 1, "Size": 4509715660u64, "Reclaimable": 1181116006u64 },
            { "Type": "Containers", "Total": 0, "Size": 0 },
            { "Type": "Local Volumes", "Total": 0, "Size": 335544320u64 }
        ]);
        apply_podman_df(&mut df, entries.as_array().unwrap());

        assert_eq!(df.images.size_bytes, Some(4509715660));
        assert_eq!(df.images.reclaimable_bytes, Some(1181116006));
        assert_eq!(df.containers.size_bytes, Some(0));
        assert_eq!(df.volumes.size_bytes, Some(335544320));
    }

    #[test]
    fn apply_df_reads_raw_size_from_real_5x_shape() {
        // Real captured `podman 5.8.2 system df --format json` shape: human
        // string `Size`/`Reclaimable` alongside integer `RawSize`/`RawReclaimable`.
        let mut df = build_system_df_from_lists(&[], &[image(1)], 0);
        let entries = serde_json::json!([
            { "Type": "Images", "Total": 212, "Active": 17,
              "Size": "56.44GB", "Reclaimable": "45.45GB (81%)",
              "RawSize": 56439884628u64, "RawReclaimable": 45448663074u64 },
            { "Type": "Containers", "Total": 6, "Active": 4,
              "Size": "95.25MB", "Reclaimable": "1.323MB (1%)",
              "RawSize": 95245121u64, "RawReclaimable": 1322852u64 },
            { "Type": "Local Volumes", "Total": 23, "Active": 6,
              "Size": "24.73GB", "Reclaimable": "12.51GB (51%)",
              "RawSize": 24732372348u64, "RawReclaimable": 12505502022u64 }
        ]);
        apply_podman_df(&mut df, entries.as_array().unwrap());

        assert_eq!(df.images.size_bytes, Some(56439884628));
        assert_eq!(df.images.reclaimable_bytes, Some(45448663074));
        assert_eq!(df.containers.size_bytes, Some(95245121));
        assert_eq!(df.volumes.size_bytes, Some(24732372348));
    }

    #[test]
    fn apply_df_ignores_non_numeric_and_unknown_types() {
        let mut df = build_system_df_from_lists(&[], &[image(7)], 0);
        let entries = serde_json::json!([
            { "Type": "Images", "Size": "1.2GB", "Reclaimable": "800MB (66%)" },
            { "Type": "BuildCache", "Size": 999 }
        ]);
        apply_podman_df(&mut df, entries.as_array().unwrap());

        // Non-numeric string sizes must not override the list-derived sum.
        assert_eq!(df.images.size_bytes, Some(7));
        assert_eq!(df.images.reclaimable_bytes, None);
        // Unknown type is ignored entirely.
        assert_eq!(df.containers.size_bytes, None);
        assert_eq!(df.volumes.size_bytes, None);
    }

    #[test]
    fn response_serializes_null_bytes_as_null_keys() {
        let df = build_system_df_from_lists(&[container(ContainerState::Running)], &[], 0);
        let v = serde_json::to_value(&df).unwrap();
        // Keys must be present even when the value is null (frontend binding).
        assert!(v["containers"]["size_bytes"].is_null());
        assert!(v["volumes"]["size_bytes"].is_null());
        assert!(v["build_cache_bytes"].is_null());
        assert_eq!(v["containers"]["running"], 1);
        assert_eq!(v["images"]["size_bytes"], 0);
    }
}
