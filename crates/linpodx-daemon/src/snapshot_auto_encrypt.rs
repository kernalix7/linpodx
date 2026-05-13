//! Phase 17 Stream B — runtime-side `SnapshotEncryptor` adapter wired into the
//! sandbox auto-encrypt hook.
//!
//! Lives in the daemon crate so the sandbox crate stays unaware of the
//! `EncryptionConfig` resolution path (it only knows the trait). The adapter
//! pulls a config from the environment via
//! [`linpodx_runtime::EncryptionConfig::from_env`] and re-uses
//! [`linpodx_runtime::snapshot::encrypt_committed_image`] under a synchronous
//! façade. When neither `LINPODX_SNAPSHOT_KEY` nor
//! `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` is set the factory returns `None` so
//! the hook stays installed but no-ops on every event (`outcome=no_encryptor`
//! in the audit trail).

use linpodx_runtime::{snapshot as runtime_snapshot, EncryptionConfig, Podman};
use linpodx_sandbox::snapshot_trigger::{
    KeySource, SandboxError, SnapshotEncryptor, TriggerResult,
};
use std::sync::Arc;
use tracing::warn;

/// Adapter that owns a clone of [`Podman`] and the resolved
/// [`EncryptionConfig`]. The hook calls [`SnapshotEncryptor::encrypt`] from a
/// sandbox-driven path; we bridge the sync trait method to the async runtime
/// call via [`tokio::runtime::Handle::block_on`] so the caller (already inside
/// a Tokio task) doesn't have to spawn a new runtime. When called from a
/// non-async context (test paths), we fall back to spawning a one-shot
/// runtime.
pub struct RuntimeSnapshotEncryptor {
    podman: Podman,
    cfg: EncryptionConfig,
}

impl RuntimeSnapshotEncryptor {
    pub fn new(podman: Podman, cfg: EncryptionConfig) -> Self {
        Self { podman, cfg }
    }
}

impl SnapshotEncryptor for RuntimeSnapshotEncryptor {
    fn encrypt(&self, image_ref: &str, _key_source: KeySource) -> TriggerResult<()> {
        // The hook supplies a `KeySource` for audit-trail provenance only; the
        // actual key bytes live on `self.cfg`. We pass `keep_local_image=true`
        // so a failed downstream user request isn't accompanied by a
        // surprise image-removal — the operator can clean up explicitly.
        let podman = self.podman.clone();
        let cfg = self.cfg.clone();
        let image = image_ref.to_string();
        let res = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(move || {
                handle.block_on(async move {
                    runtime_snapshot::encrypt_committed_image(&podman, &image, &cfg, true).await
                })
            }),
            Err(_) => {
                // No ambient runtime — build a minimal one. Only used by
                // unit-test paths that exercise the trait directly.
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| SandboxError::Encryptor(format!("build temp runtime: {e}")))?;
                rt.block_on(async move {
                    runtime_snapshot::encrypt_committed_image(&podman, &image, &cfg, true).await
                })
            }
        };
        match res {
            Ok(_meta) => Ok(()),
            Err(e) => Err(SandboxError::Encryptor(e.to_string())),
        }
    }
}

/// Resolve a runtime-side encryptor from the environment. `None` means no
/// encryption config is configured — caller leaves the hook un-encryptored.
pub fn make_encryptor(podman: &Podman) -> Option<Arc<dyn SnapshotEncryptor>> {
    match EncryptionConfig::from_env() {
        Ok(Some(cfg)) => Some(Arc::new(RuntimeSnapshotEncryptor::new(podman.clone(), cfg))),
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, "snapshot encryption env vars set but invalid; hook stays without encryptor");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_runtime::snapshot_crypto::KeySource;

    #[test]
    fn make_encryptor_returns_none_when_env_unset() {
        // Snapshot then clear both env vars so the test is hermetic regardless
        // of the operator's shell.
        let key_prev = std::env::var("LINPODX_SNAPSHOT_KEY").ok();
        let pass_prev = std::env::var("LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE").ok();
        std::env::remove_var("LINPODX_SNAPSHOT_KEY");
        std::env::remove_var("LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE");

        let podman = Podman::default();
        let result = make_encryptor(&podman);
        assert!(result.is_none());

        if let Some(v) = key_prev {
            std::env::set_var("LINPODX_SNAPSHOT_KEY", v);
        }
        if let Some(v) = pass_prev {
            std::env::set_var("LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE", v);
        }
    }

    #[test]
    fn adapter_holds_cfg_and_podman() {
        let podman = Podman::default();
        let cfg = EncryptionConfig::from_key([0u8; 32]);
        let adapter = RuntimeSnapshotEncryptor::new(podman, cfg.clone());
        assert_eq!(adapter.cfg.key_source, KeySource::Explicit);
    }
}
