#![forbid(unsafe_code)]

pub mod egress_enforcer;
pub mod image;
pub mod metrics;
pub mod network;
pub mod network_filter;
pub mod oci_tar;
pub mod overlayfs;
pub mod parse;
pub mod passthrough;
pub mod pod;
pub mod podman;
pub mod secret;
pub mod snapshot;
pub mod snapshot_crypto;
pub mod snapshot_key_rotation;
pub mod version;
pub mod volume;

pub use egress_enforcer::EgressEnforcer;
pub use linpodx_common::ipc::CreateOptions;
pub use metrics::{MetricsCollector, RingBuffer, RING_CAPACITY};
pub use network_filter::{start as start_egress_filter, FilterHandle};
pub use oci_tar::{list_files_in_oci, save_image, FileEntry};
pub use overlayfs::{
    ensure_dirs, fuse_overlayfs_available, image_dir, mount_layers, mount_path, read_meta,
    store_root, write_meta, LayerDirs, MountedRoot, OverlayMeta,
};
pub use passthrough::{apply_passthrough, HostEnv, SystemHostEnv};
pub use pod::{pod_create, pod_list, pod_remove, pod_start, pod_stop};
pub use podman::{
    exec_pty, make_bridge_id, ExecOptions, ExecOutput, LogOptions, LogsOutput, Podman,
    PodmanConfig, PtyExecOptions, PtyHandle, StreamKind,
};
pub use snapshot::{
    backend_for, backend_list, set_overlayfs_audit_sink, BtrfsBackend, OverlayfsBackend,
    PodmanCommitBackend, SnapshotBackend,
};
pub use snapshot_crypto::{
    decrypt_bytes, derive_key, derive_key_argon2id, derive_key_from_passphrase,
    derive_key_sha256_rounds, encrypt_bytes, key_from_base64, sha256_hex, CryptoError,
    EncryptionConfig, Kdf, KeySource, ALGORITHM as SNAPSHOT_ENCRYPT_ALGORITHM, ENV_KDF, ENV_KEY,
    ENV_PASSPHRASE, KDF_ID_ARGON2ID, KDF_ID_SHA256_ROUNDS, KEY_LEN as SNAPSHOT_KEY_LEN,
    NONCE_LEN as SNAPSHOT_NONCE_LEN,
};
pub use snapshot_key_rotation::{
    re_encrypt_all, rotate_snapshot_key, NewKeySource, ReEncryptAllOutcome, RotateOutcome,
};
