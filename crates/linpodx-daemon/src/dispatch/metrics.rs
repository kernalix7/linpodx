//! Live container metrics dispatch handlers (Phase 6).

use super::*;

impl Dispatcher {
    pub(crate) async fn metrics_latest(
        &self,
        p: linpodx_common::ipc::MetricsLatestParams,
    ) -> Result<serde_json::Value> {
        let latest = self.metrics.latest(&p.container_id).await;
        if latest.is_none() {
            // Lazy warm-up: no sample buffered yet (e.g. the first UI request
            // for a container started directly via podman, before the reconcile
            // loop's next tick). Spawning is idempotent; the next poll returns
            // data. This call returns `null` this once.
            self.metrics.spawn_for(p.container_id.clone()).await;
        }
        Ok(serde_json::to_value(latest)?)
    }

    pub(crate) async fn metrics_history(
        &self,
        p: linpodx_common::ipc::MetricsHistoryParams,
    ) -> Result<serde_json::Value> {
        let since = p.since.as_deref().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc))
        });
        let samples = self.metrics.history(&p.container_id, since).await;
        if samples.is_empty() {
            // Same lazy warm-up as `metrics_latest`.
            self.metrics.spawn_for(p.container_id.clone()).await;
        }
        Ok(serde_json::to_value(samples)?)
    }
}
