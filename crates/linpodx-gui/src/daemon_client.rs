//! Phase 17 — daemon IPC wrapper for the GUI's new Stream A/B/C surfaces.
//!
//! The Phase-1B `connection.rs` module already owns the long-lived UNIX socket
//! subscription and a `one_shot` helper for fire-and-forget RPCs. This module
//! layers the Phase 17 dispatch arms on top of that helper as `async fn`s that
//! return `Message` so the iced `update` layer can dispatch them via
//! `iced::Task::perform`.
//!
//! Each function:
//!   1. opens a one-shot connection,
//!   2. fires the matching `Method::*` with the supplied params,
//!   3. parses the typed response and returns the matching `Message`,
//!   4. logs at `warn` on transport / RPC failure and returns `Message::NoOp`.
//!
//! Until the Stream A/B/C teams fill in the daemon-side arms the daemon will
//! reply with a not-yet-implemented `Error::Runtime`; this module surfaces that
//! as a logged warning rather than a panic, so the GUI keeps rendering.

use crate::connection::one_shot;
use crate::state::Message;
use linpodx_common::ipc::responses::{
    DaemonPinClientTofuExpirySetResponse, DaemonPinClientTofuExpiryStatusResponse,
    PluginKeyListResponse, PluginKeyRevokePropagateResponse,
    SandboxSnapshotAutoTriggerStatusResponse, SnapshotEncryptionStatusResponse,
    SnapshotKeyRotateResponse, SnapshotReEncryptAllResponse,
};
use linpodx_common::ipc::{
    DaemonPinClientTofuExpirySetParams, Method, PluginKeyRevokePropagateParams,
    SandboxSnapshotAutoTriggerEnableParams, SnapshotIdParams, SnapshotKeyRotateParams,
    SnapshotKeySource, SnapshotReEncryptAllParams,
};
use std::path::PathBuf;
use tracing::warn;

/// Phase 17 Stream A — request a per-snapshot key rotation with a new
/// passphrase. The daemon returns the new algorithm and KDF identifiers; we
/// thread them back into the GUI's `snapshot_encryption_badges` cache.
pub async fn send_snapshot_key_rotate(
    socket: PathBuf,
    snapshot_id: i64,
    new_passphrase: String,
) -> Message {
    let params = SnapshotKeyRotateParams {
        snapshot_id,
        new_key: SnapshotKeySource::Passphrase {
            passphrase: new_passphrase,
        },
    };
    match one_shot::<SnapshotKeyRotateResponse>(&socket, Method::SnapshotKeyRotate(params)).await {
        Ok(resp) => Message::SnapshotKeyRotated {
            snapshot_id: resp.snapshot_id,
            algorithm: resp.algorithm,
            kdf: resp.kdf,
        },
        Err(e) => {
            warn!(error = %e, snapshot_id, "snapshot_key_rotate rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream A — request a bulk re-encryption of every encrypted
/// snapshot using a single new passphrase. The daemon streams progress events
/// over the existing Snapshot topic; this call returns the final tally.
pub async fn send_snapshot_re_encrypt_all(socket: PathBuf, new_passphrase: String) -> Message {
    let params = SnapshotReEncryptAllParams {
        new_key: SnapshotKeySource::Passphrase {
            passphrase: new_passphrase,
        },
    };
    match one_shot::<SnapshotReEncryptAllResponse>(&socket, Method::SnapshotReEncryptAll(params))
        .await
    {
        Ok(resp) => Message::SnapshotReEncryptAllDone {
            total_seen: resp.total_seen,
            re_encrypted: resp.re_encrypted,
            skipped: resp.skipped,
            failed: resp.failed,
        },
        Err(e) => {
            warn!(error = %e, "snapshot_re_encrypt_all rpc failed");
            Message::NoOp
        }
    }
}

/// Load the encryption metadata for a single snapshot so the row badge knows
/// the kdf / algorithm. Returns `NoOp` when the snapshot isn't encrypted or
/// the daemon hasn't wired up the Stream A response yet.
pub async fn load_snapshot_encryption(socket: PathBuf, snapshot_id: i64) -> Message {
    match one_shot::<SnapshotEncryptionStatusResponse>(
        &socket,
        Method::SnapshotEncryptionStatus(SnapshotIdParams { id: snapshot_id }),
    )
    .await
    {
        Ok(resp) => Message::SnapshotEncryptionLoaded(resp),
        Err(e) => {
            warn!(error = %e, snapshot_id, "snapshot_encryption_status rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream C — fetch the TOFU expiry status (enabled / max_age_secs /
/// enabled_at) so the PinnedClients tab can render the countdown.
pub async fn load_tofu_expiry_status(socket: PathBuf) -> Message {
    match one_shot::<DaemonPinClientTofuExpiryStatusResponse>(
        &socket,
        Method::DaemonPinClientTofuExpiryStatus,
    )
    .await
    {
        Ok(resp) => Message::TofuExpiryLoaded(resp),
        Err(e) => {
            warn!(error = %e, "tofu_expiry_status rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream C — push a new `max_age_secs` (or `None` to clear).
pub async fn set_tofu_expiry(socket: PathBuf, max_age_secs: Option<u64>) -> Message {
    match one_shot::<DaemonPinClientTofuExpirySetResponse>(
        &socket,
        Method::DaemonPinClientTofuExpirySet(DaemonPinClientTofuExpirySetParams { max_age_secs }),
    )
    .await
    {
        Ok(resp) => Message::TofuExpiryUpdated(resp.max_age_secs),
        Err(e) => {
            warn!(error = %e, ?max_age_secs, "tofu_expiry_set rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream C — fetch the plugin key registry.
pub async fn load_plugin_keys(socket: PathBuf) -> Message {
    match one_shot::<PluginKeyListResponse>(&socket, Method::PluginKeyList).await {
        Ok(keys) => Message::PluginKeysLoaded(keys),
        Err(e) => {
            warn!(error = %e, "plugin_key_list rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream C — propagate a plugin key revocation through Raft.
pub async fn send_plugin_key_revoke_propagate(
    socket: PathBuf,
    publisher: String,
    fingerprint: String,
    reason: Option<String>,
) -> Message {
    let params = PluginKeyRevokePropagateParams {
        publisher: publisher.clone(),
        fingerprint: fingerprint.clone(),
        reason,
    };
    match one_shot::<PluginKeyRevokePropagateResponse>(
        &socket,
        Method::PluginKeyRevokePropagate(params),
    )
    .await
    {
        Ok(resp) => Message::PluginKeyRevokePropagated {
            publisher: resp.publisher,
            fingerprint: resp.fingerprint,
            log_index: resp.log_index,
        },
        Err(e) => {
            warn!(error = %e, %publisher, %fingerprint, "plugin_key_revoke_propagate rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream B — fetch the sandbox snapshot auto-trigger status.
pub async fn load_sandbox_auto_trigger(socket: PathBuf) -> Message {
    match one_shot::<SandboxSnapshotAutoTriggerStatusResponse>(
        &socket,
        Method::SandboxSnapshotAutoTriggerStatus,
    )
    .await
    {
        Ok(resp) => Message::SandboxAutoTriggerLoaded(resp),
        Err(e) => {
            warn!(error = %e, "sandbox_auto_trigger_status rpc failed");
            Message::NoOp
        }
    }
}

/// Phase 17 Stream B — flip the sandbox auto-trigger on/off. Refresh comes via
/// a follow-up `load_sandbox_auto_trigger` call.
pub async fn set_sandbox_auto_trigger(socket: PathBuf, enabled: bool) -> Message {
    if let Err(e) = one_shot::<SandboxSnapshotAutoTriggerStatusResponse>(
        &socket,
        Method::SandboxSnapshotAutoTriggerEnable(SandboxSnapshotAutoTriggerEnableParams {
            enabled,
        }),
    )
    .await
    {
        warn!(error = %e, enabled, "sandbox_auto_trigger_enable rpc failed");
    }
    // The toggle reducer already flipped the cached `enabled` flag; a successful
    // call lets the daemon push a Sandbox event which will trigger a re-fetch.
    Message::NoOp
}

/// Helper used by the PinnedClients view: parses the user's "set expiry" input
/// (free-form digits, possibly with a trailing unit suffix) and returns either
/// a normalised seconds value, `None` to clear the expiry, or an error string
/// for inline rendering. Kept pure-Rust so it stays unit-testable on host.
pub fn parse_expiry_input(raw: &str) -> Result<Option<u64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.eq_ignore_ascii_case("clear") || trimmed.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    // Accept a single optional suffix: s / m / h / d. No suffix → seconds.
    let (number_part, multiplier): (&str, u64) =
        if let Some(rest) = trimmed.strip_suffix(['s', 'S']) {
            (rest, 1)
        } else if let Some(rest) = trimmed.strip_suffix(['m', 'M']) {
            (rest, 60)
        } else if let Some(rest) = trimmed.strip_suffix(['h', 'H']) {
            (rest, 3600)
        } else if let Some(rest) = trimmed.strip_suffix(['d', 'D']) {
            (rest, 86_400)
        } else {
            (trimmed, 1)
        };
    let n: u64 = number_part.trim().parse().map_err(|_| {
        format!("invalid expiry value: {raw:?} (expected digits, optional s/m/h/d)")
    })?;
    if n == 0 {
        return Err("expiry must be greater than zero (use 'clear' to disable)".into());
    }
    Ok(Some(n.saturating_mul(multiplier)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_expiry_input_handles_blank_and_clear() {
        assert_eq!(parse_expiry_input("").unwrap(), None);
        assert_eq!(parse_expiry_input("   ").unwrap(), None);
        assert_eq!(parse_expiry_input("clear").unwrap(), None);
        assert_eq!(parse_expiry_input("NONE").unwrap(), None);
    }

    #[test]
    fn parse_expiry_input_accepts_bare_seconds() {
        assert_eq!(parse_expiry_input("60").unwrap(), Some(60));
        assert_eq!(parse_expiry_input("3600").unwrap(), Some(3600));
    }

    #[test]
    fn parse_expiry_input_accepts_unit_suffixes() {
        assert_eq!(parse_expiry_input("30s").unwrap(), Some(30));
        assert_eq!(parse_expiry_input("5m").unwrap(), Some(300));
        assert_eq!(parse_expiry_input("2h").unwrap(), Some(7_200));
        assert_eq!(parse_expiry_input("1d").unwrap(), Some(86_400));
        // Suffix matching is ASCII case-insensitive.
        assert_eq!(parse_expiry_input("10S").unwrap(), Some(10));
    }

    #[test]
    fn parse_expiry_input_rejects_zero_and_garbage() {
        assert!(parse_expiry_input("0").is_err());
        assert!(parse_expiry_input("-1").is_err());
        assert!(parse_expiry_input("oops").is_err());
        assert!(parse_expiry_input("60x").is_err());
    }
}
