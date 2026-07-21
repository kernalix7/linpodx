//! Live container metrics dispatch handlers (Phase 6).

use super::*;

impl Dispatcher {
    pub(crate) async fn metrics_latest(
        &self,
        p: linpodx_common::ipc::MetricsLatestParams,
    ) -> Result<serde_json::Value> {
        let latest = self.metrics.latest(&p.container_id).await;
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
        Ok(serde_json::to_value(samples)?)
    }
}
