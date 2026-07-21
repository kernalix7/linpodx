//! WS client-cert pinning + TOFU (Trust-On-First-Use) dispatch handlers.

use super::*;

impl Dispatcher {
    pub(crate) async fn daemon_pin_client_tofu_enable(
        &self,
        p: linpodx_common::ipc::DaemonPinClientTofuEnableParams,
    ) -> Result<serde_json::Value> {
        {
            let mut mode = self
                .tofu
                .lock()
                .map_err(|_| Error::Internal("tofu mode lock poisoned".into()))?;
            let was_enabled = mode.enabled;
            mode.enabled = p.enable;
            mode.max_enrollments = p.max_enrollments;
            if p.enable {
                // Capture the enable timestamp once per off->on edge so
                // the Phase 17 `max_age_secs` window has a stable anchor.
                // Re-enabling while already enabled does NOT reset the
                // anchor (so an operator tweaking `max_enrollments`
                // mid-window does not accidentally extend the deadline).
                if !was_enabled {
                    mode.enabled_at = Some(chrono::Utc::now().timestamp());
                    mode.current_count = 0;
                }
            } else {
                // Disabling resets every Phase 16/17 field so the next
                // --enable starts with a fresh budget + window.
                mode.current_count = 0;
                mode.enabled_at = None;
                mode.max_age_secs = None;
            }
        }
        let resp = responses::DaemonPinClientTofuEnableResponse {
            enabled: p.enable,
            max_enrollments: p.max_enrollments,
        };
        Ok(serde_json::to_value(resp)?)
    }

    // ----- Phase 17 Stream C — TOFU time-based expiry status / set.
    pub(crate) async fn daemon_pin_client_tofu_expiry_status(&self) -> Result<serde_json::Value> {
        let snapshot = {
            let mode = self
                .tofu
                .lock()
                .map_err(|_| Error::Internal("tofu mode lock poisoned".into()))?;
            (mode.enabled, mode.max_age_secs, mode.enabled_at)
        };
        let resp = responses::DaemonPinClientTofuExpiryStatusResponse {
            enabled: snapshot.0,
            max_age_secs: snapshot.1,
            enabled_at: snapshot.2,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn daemon_pin_client_tofu_expiry_set(
        &self,
        p: linpodx_common::ipc::DaemonPinClientTofuExpirySetParams,
    ) -> Result<serde_json::Value> {
        {
            let mut mode = self
                .tofu
                .lock()
                .map_err(|_| Error::Internal("tofu mode lock poisoned".into()))?;
            if !mode.enabled {
                return Err(Error::InvalidArgument(
                    "tofu mode is currently disabled; \
                     enable it first via daemon pin-client tofu --enable"
                        .into(),
                ));
            }
            if mode.enabled_at.is_none() {
                // Backfill the anchor: the only path to a `None` anchor
                // with `enabled=true` is a daemon that flipped TOFU on
                // before Phase 17 (or a hand-crafted test). Use the
                // current wall clock so the window starts here.
                mode.enabled_at = Some(chrono::Utc::now().timestamp());
            }
            mode.max_age_secs = p.max_age_secs;
        }
        let resp = responses::DaemonPinClientTofuExpirySetResponse {
            max_age_secs: p.max_age_secs,
        };
        Ok(serde_json::to_value(resp)?)
    }

    // ----- Phase 15: WS client cert pinning (Stream C) -----
    pub(crate) async fn daemon_pin_client_add(
        &self,
        p: linpodx_common::ipc::DaemonPinClientAddParams,
    ) -> Result<serde_json::Value> {
        let (fingerprint, inserted) = self
            .pin_store
            .add_from_pem(p.cert_pem.as_bytes(), &p.label)
            .await?;
        let resp = responses::DaemonPinClientAddResponse {
            fingerprint,
            inserted,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn daemon_pin_client_list(&self) -> Result<serde_json::Value> {
        let listed = self.pin_store.list().await?;
        Ok(serde_json::to_value::<
            responses::DaemonPinClientListResponse,
        >(listed)?)
    }

    pub(crate) async fn daemon_pin_client_remove(
        &self,
        p: linpodx_common::ipc::DaemonPinClientRemoveParams,
    ) -> Result<serde_json::Value> {
        let removed = self.pin_store.remove(&p.fingerprint).await?;
        let resp = responses::DaemonPinClientRemoveResponse {
            fingerprint: p.fingerprint,
            removed,
        };
        Ok(serde_json::to_value(resp)?)
    }
}
