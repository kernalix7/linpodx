//! Phase 16 Stream B — at-rest encryption for snapshot artefacts.
//!
//! Self-contained AES-256-GCM helpers used by [`crate::snapshot`] when the
//! daemon is launched with `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` (KDF) or
//! `LINPODX_SNAPSHOT_KEY` (raw base64 key). Output layout is
//! `nonce(12) || ciphertext || tag(16)` — the tag is appended automatically by
//! `aes-gcm`'s `encrypt()`. Format is intentionally simple so a future
//! migration to streaming AEAD can replace it without disturbing callers.
//!
//! Phase 17 Stream A — KDF hardening. The legacy Phase 16 KDF was a
//! deterministic 1000-round SHA-256 chain over `salt || passphrase || counter`;
//! retained as [`Kdf::Sha256Rounds`] for backward compatibility with
//! already-encrypted snapshots. Default is now [`Kdf::Argon2id`] with the
//! OWASP 2023+ parameters (m_cost = 19 MiB, t_cost = 2, p_cost = 1) — see the
//! OWASP Password Storage Cheat Sheet, "Argon2id" section.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const ALGORITHM: &str = "aes-256-gcm";

/// Stable salt prefix mixed into the KDF so two daemons with the same
/// passphrase still derive a deterministic key. Operators wanting a per-host
/// key should set `LINPODX_SNAPSHOT_KEY` directly.
pub const KDF_SALT_DEFAULT: &[u8; 16] = b"linpodx-snap/v1.";

/// Environment variable that holds a raw base64-encoded 32-byte key. Higher
/// priority than the passphrase variable when both are set.
pub const ENV_KEY: &str = "LINPODX_SNAPSHOT_KEY";
/// Environment variable that holds a passphrase. Mixed through
/// [`derive_key_from_passphrase`] with the default salt.
pub const ENV_PASSPHRASE: &str = "LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE";
/// Phase 17 — select the KDF. Accepted values: `argon2id` (default),
/// `sha256-1k` (legacy 1000-round SHA-256, kept for Phase 16 compatibility).
pub const ENV_KDF: &str = "LINPODX_SNAPSHOT_KDF";

/// Legacy SHA-256 round count baked into Phase 16. Used by both
/// [`Kdf::Sha256Rounds`] default and the on-disk fallback when a meta.json
/// side-car has no `kdf` field.
pub const LEGACY_SHA256_ROUNDS: u32 = 1000;

// ---- Argon2id parameters (OWASP Password Storage Cheat Sheet, 2023+) ----
// "m=19456 (19 MiB), t=2, p=1" — yields ~30 ms on modern hardware while still
// dominating the work factor over the AEAD itself. Documented intentionally
// in source so future rotations stay reviewable.
pub const ARGON2_DEFAULT_M_COST_KIB: u32 = 19_456;
pub const ARGON2_DEFAULT_T_COST: u32 = 2;
pub const ARGON2_DEFAULT_P_COST: u32 = 1;

/// Identifier persisted in meta.json's `kdf.kind` field.
pub const KDF_ID_ARGON2ID: &str = "argon2id";
/// Identifier persisted in meta.json's `kdf.kind` field for the legacy
/// 1000-round SHA-256 chain.
pub const KDF_ID_SHA256_ROUNDS: &str = "sha256-rounds";

/// Key-derivation algorithm selector. Persisted inside
/// [`crate::snapshot::EncryptedSnapshotMeta`]'s `kdf` field so a future rotation
/// can re-derive without guessing parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Kdf {
    /// OWASP-recommended Argon2id (m_cost in KiB, t_cost iterations, p_cost
    /// parallelism). Default — every new snapshot uses this unless the
    /// operator opts into legacy mode via `LINPODX_SNAPSHOT_KDF=sha256-1k`.
    Argon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
    /// Phase 16 legacy: deterministic 1000-round SHA-256. Retained so existing
    /// encrypted snapshots from Phase 16 daemons still decrypt without
    /// migration; new snapshots should prefer `Argon2id`.
    #[serde(rename = "sha256-rounds")]
    Sha256Rounds { rounds: u32 },
}

impl Default for Kdf {
    fn default() -> Self {
        Self::argon2id_default()
    }
}

impl Kdf {
    /// OWASP-recommended Argon2id parameters (2023+ guidance).
    pub fn argon2id_default() -> Self {
        Self::Argon2id {
            m_cost: ARGON2_DEFAULT_M_COST_KIB,
            t_cost: ARGON2_DEFAULT_T_COST,
            p_cost: ARGON2_DEFAULT_P_COST,
        }
    }

    /// Legacy Phase 16 SHA-256 chain (1000 rounds).
    pub fn sha256_legacy() -> Self {
        Self::Sha256Rounds {
            rounds: LEGACY_SHA256_ROUNDS,
        }
    }

    /// Human-readable id used by audit log `kdf` fields and IPC responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Argon2id { .. } => KDF_ID_ARGON2ID,
            Self::Sha256Rounds { .. } => KDF_ID_SHA256_ROUNDS,
        }
    }

    /// Parse the `LINPODX_SNAPSHOT_KDF` env var. Returns the default when unset
    /// or empty. Unknown values bubble up as a [`CryptoError::KdfUnknown`].
    pub fn from_env_var(raw: &str) -> Result<Self, CryptoError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self::argon2id_default());
        }
        match trimmed.to_ascii_lowercase().as_str() {
            "argon2id" => Ok(Self::argon2id_default()),
            "sha256-1k" | "sha256-rounds" => Ok(Self::sha256_legacy()),
            other => Err(CryptoError::KdfUnknown(other.to_string())),
        }
    }
}

/// Encryption configuration derived once at backend construction time.
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Raw 32-byte AES key.
    pub key: [u8; KEY_LEN],
    /// Algorithm identifier persisted on the snapshots row. Always
    /// `"aes-256-gcm"` for v0.1.
    pub algorithm: &'static str,
    /// Provenance tag persisted on the snapshots row: `"env"` (raw key),
    /// `"passphrase"` (KDF), or `"explicit"` (constructed in tests).
    pub key_source: KeySource,
    /// KDF used to derive `key` from the source material. For
    /// [`KeySource::Env`] / [`KeySource::Explicit`] the key was supplied
    /// directly — we still record an entry (`Argon2id` for forward-compat)
    /// so the meta.json schema is uniform.
    pub kdf: Kdf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Env,
    Passphrase,
    Explicit,
}

impl KeySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Passphrase => "passphrase",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ciphertext shorter than nonce length")]
    ShortBlob,
    #[error("AEAD decrypt failed (wrong key, tampered ciphertext, or wrong nonce)")]
    Decrypt,
    #[error("invalid base64 key in {ENV_KEY}: {0}")]
    KeyDecode(String),
    #[error("{ENV_KEY} key length must be {KEY_LEN} bytes after base64 decode, got {0}")]
    KeyLength(usize),
    #[error("environment variable {0} is not set")]
    NotConfigured(&'static str),
    #[error("AEAD encrypt failed")]
    Encrypt,
    #[error("argon2 KDF failed")]
    Argon2(#[source] argon2::Error),
    #[error("invalid argon2 parameters (m_cost={m_cost}, t_cost={t_cost}, p_cost={p_cost})")]
    Argon2Params {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        #[source]
        source: argon2::Error,
    },
    #[error("unknown KDF identifier `{0}` (expected `argon2id` or `sha256-1k`)")]
    KdfUnknown(String),
}

impl EncryptionConfig {
    /// Build a config from an explicit key — primarily for tests.
    pub fn from_key(key: [u8; KEY_LEN]) -> Self {
        Self {
            key,
            algorithm: ALGORITHM,
            key_source: KeySource::Explicit,
            kdf: Kdf::argon2id_default(),
        }
    }

    /// Build a config from a passphrase using the default salt and the default
    /// KDF (Argon2id).
    pub fn from_passphrase(passphrase: &str) -> Self {
        Self::from_passphrase_with_kdf(passphrase, Kdf::argon2id_default()).unwrap_or_else(|_| {
            // Argon2 with default params is well-known to be valid; fall
            // back to the legacy KDF if argon2 itself refuses (e.g. a
            // future feature flag drop). This branch is unreachable for
            // the in-tree parameters but keeps the API total.
            let key = derive_key_sha256_rounds(passphrase, KDF_SALT_DEFAULT, LEGACY_SHA256_ROUNDS);
            Self {
                key,
                algorithm: ALGORITHM,
                key_source: KeySource::Passphrase,
                kdf: Kdf::sha256_legacy(),
            }
        })
    }

    /// Build a config from a passphrase + explicit KDF choice. Used by env
    /// resolution and key-rotation flows.
    pub fn from_passphrase_with_kdf(passphrase: &str, kdf: Kdf) -> Result<Self, CryptoError> {
        let key = derive_key(passphrase.as_bytes(), KDF_SALT_DEFAULT, &kdf)?;
        Ok(Self {
            key,
            algorithm: ALGORITHM,
            key_source: KeySource::Passphrase,
            kdf,
        })
    }

    /// Resolve the active config from environment variables. `None` when
    /// neither variable is set (encryption stays disabled — backward compat).
    pub fn from_env() -> Result<Option<Self>, CryptoError> {
        if let Ok(raw) = std::env::var(ENV_KEY) {
            if !raw.is_empty() {
                let key = key_from_base64(&raw)?;
                return Ok(Some(Self {
                    key,
                    algorithm: ALGORITHM,
                    key_source: KeySource::Env,
                    kdf: Kdf::argon2id_default(),
                }));
            }
        }
        if let Ok(raw) = std::env::var(ENV_PASSPHRASE) {
            if !raw.is_empty() {
                let kdf = match std::env::var(ENV_KDF) {
                    Ok(v) => Kdf::from_env_var(&v)?,
                    Err(_) => Kdf::argon2id_default(),
                };
                return Ok(Some(Self::from_passphrase_with_kdf(&raw, kdf)?));
            }
        }
        Ok(None)
    }
}

/// Encrypt `plain` with `cfg`. Returns `nonce || ciphertext+tag`. The nonce is
/// drawn from `OsRng` so two encryptions of the same plaintext under the same
/// key produce different blobs.
pub fn encrypt_bytes(plain: &[u8], cfg: &EncryptionConfig) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new((&cfg.key).into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt the layout produced by [`encrypt_bytes`].
pub fn decrypt_bytes(blob: &[u8], cfg: &EncryptionConfig) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::ShortBlob);
    }
    let cipher = Aes256Gcm::new((&cfg.key).into());
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| CryptoError::Decrypt)
}

/// KDF dispatch: derive the 32-byte AES key for the requested algorithm.
/// `salt` is mixed deterministically; callers that want per-host keys should
/// supply [`KDF_SALT_DEFAULT`] (the default) or read a host-specific salt.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; 16],
    kdf: &Kdf,
) -> Result<[u8; KEY_LEN], CryptoError> {
    match *kdf {
        Kdf::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => derive_key_argon2id(passphrase, salt, m_cost, t_cost, p_cost),
        Kdf::Sha256Rounds { rounds } => {
            let passphrase_str = std::str::from_utf8(passphrase).unwrap_or("");
            Ok(derive_key_sha256_rounds(passphrase_str, salt, rounds))
        }
    }
}

/// Argon2id KDF, output length = 32 bytes (AES-256 key). Uses Argon2 v0x13
/// (RFC 9106).
pub fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN)).map_err(|source| {
        CryptoError::Argon2Params {
            m_cost,
            t_cost,
            p_cost,
            source,
        }
    })?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    hasher
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(CryptoError::Argon2)?;
    Ok(out)
}

/// Deterministic N-round SHA-256 over `salt || passphrase || counter`. Phase
/// 16 legacy KDF — retained so already-encrypted snapshots still decrypt. New
/// snapshots prefer [`derive_key_argon2id`].
pub fn derive_key_sha256_rounds(passphrase: &str, salt: &[u8; 16], rounds: u32) -> [u8; KEY_LEN] {
    let mut state: [u8; 32] = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(passphrase.as_bytes());
    state.copy_from_slice(&hasher.finalize());
    for round in 1u32..rounds {
        let mut h = Sha256::new();
        h.update(state);
        h.update(round.to_be_bytes());
        h.update(salt);
        state.copy_from_slice(&h.finalize());
    }
    state
}

/// Phase 16 compatibility shim — the original 1000-round SHA-256 KDF. New
/// callers should use [`derive_key`] with an explicit [`Kdf`].
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8; 16]) -> [u8; KEY_LEN] {
    derive_key_sha256_rounds(passphrase, salt, LEGACY_SHA256_ROUNDS)
}

/// Parse a base64-encoded 32-byte key.
pub fn key_from_base64(raw: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| CryptoError::KeyDecode(e.to_string()))?;
    if bytes.len() != KEY_LEN {
        return Err(CryptoError::KeyLength(bytes.len()));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Sha256 of `bytes` as lowercase hex — used for the `ciphertext_sha256`
/// audit / DB column.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, slot) in k.iter_mut().enumerate() {
            *slot = i as u8;
        }
        k
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let cfg = EncryptionConfig::from_key(fixed_key());
        let plain = b"hello, snapshot";
        let blob = encrypt_bytes(plain, &cfg).expect("encrypt");
        // Layout sanity: nonce + ct + tag.
        assert!(blob.len() >= NONCE_LEN + TAG_LEN);
        let recovered = decrypt_bytes(&blob, &cfg).expect("decrypt");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn nonce_is_unique_per_call() {
        let cfg = EncryptionConfig::from_key(fixed_key());
        let a = encrypt_bytes(b"same", &cfg).unwrap();
        let b = encrypt_bytes(b"same", &cfg).unwrap();
        // Identical plaintext under same key still differs because nonce changes.
        assert_ne!(a, b);
        // But the nonce prefix length is consistent.
        assert_eq!(&a[..NONCE_LEN].len(), &b[..NONCE_LEN].len());
    }

    #[test]
    fn wrong_key_rejects_decrypt() {
        let cfg_a = EncryptionConfig::from_key(fixed_key());
        let mut other = fixed_key();
        other[0] ^= 0xff;
        let cfg_b = EncryptionConfig::from_key(other);
        let blob = encrypt_bytes(b"payload", &cfg_a).unwrap();
        match decrypt_bytes(&blob, &cfg_b) {
            Err(CryptoError::Decrypt) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    #[test]
    fn tampered_nonce_rejects_decrypt() {
        let cfg = EncryptionConfig::from_key(fixed_key());
        let mut blob = encrypt_bytes(b"payload", &cfg).unwrap();
        // Flip a bit in the nonce.
        blob[0] ^= 0x01;
        match decrypt_bytes(&blob, &cfg) {
            Err(CryptoError::Decrypt) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    #[test]
    fn short_blob_returns_short_blob_err() {
        let cfg = EncryptionConfig::from_key(fixed_key());
        let blob = vec![0u8; NONCE_LEN]; // missing ciphertext + tag
        match decrypt_bytes(&blob, &cfg) {
            Err(CryptoError::ShortBlob) => {}
            other => panic!("expected ShortBlob, got {other:?}"),
        }
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let a = derive_key_from_passphrase("hunter2", KDF_SALT_DEFAULT);
        let b = derive_key_from_passphrase("hunter2", KDF_SALT_DEFAULT);
        assert_eq!(a, b);
        let c = derive_key_from_passphrase("hunter3", KDF_SALT_DEFAULT);
        assert_ne!(a, c);
    }

    #[test]
    fn key_derivation_changes_with_salt() {
        let salt_a = b"salt-aaaaaaaaaaa";
        let salt_b = b"salt-bbbbbbbbbbb";
        let a = derive_key_from_passphrase("same", salt_a);
        let b = derive_key_from_passphrase("same", salt_b);
        assert_ne!(a, b);
    }

    #[test]
    fn key_from_base64_round_trip() {
        let raw = base64::engine::general_purpose::STANDARD.encode(fixed_key());
        let k = key_from_base64(&raw).expect("decode");
        assert_eq!(k, fixed_key());
    }

    #[test]
    fn key_from_base64_rejects_wrong_length() {
        // 16 bytes only.
        let raw = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        match key_from_base64(&raw) {
            Err(CryptoError::KeyLength(16)) => {}
            other => panic!("expected KeyLength(16), got {other:?}"),
        }
    }

    #[test]
    fn key_from_base64_rejects_garbage() {
        match key_from_base64("not base64!!!") {
            Err(CryptoError::KeyDecode(_)) => {}
            other => panic!("expected KeyDecode, got {other:?}"),
        }
    }

    #[test]
    fn sha256_hex_is_64_chars_lower() {
        let h = sha256_hex(b"abc");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        // Known sha256("abc")
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hex_is_stable_between_calls() {
        let blob = b"deterministic input";
        let a = sha256_hex(blob);
        let b = sha256_hex(blob);
        assert_eq!(a, b);
    }

    /// Locks in the on-disk format so future refactors don't silently break
    /// previously-encrypted snapshots. If this assertion ever changes,
    /// existing encrypted snapshot directories must be migrated.
    #[test]
    fn format_layout_is_nonce_then_aead() {
        let cfg = EncryptionConfig::from_key(fixed_key());
        let plain = b"x";
        let blob = encrypt_bytes(plain, &cfg).unwrap();
        // 12 nonce + 1 byte ciphertext + 16 tag = 29.
        assert_eq!(blob.len(), NONCE_LEN + plain.len() + TAG_LEN);
    }

    // ----- Phase 17 Stream A — argon2id + Kdf enum tests -----

    #[test]
    fn argon2id_default_round_trip() {
        let cfg = EncryptionConfig::from_passphrase("phase17-passphrase");
        assert!(matches!(cfg.kdf, Kdf::Argon2id { .. }));
        let plain = b"argon2 protected snapshot blob";
        let blob = encrypt_bytes(plain, &cfg).expect("encrypt");
        let recovered = decrypt_bytes(&blob, &cfg).expect("decrypt");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn argon2id_is_deterministic_for_same_inputs() {
        let a = derive_key_argon2id(
            b"hunter2",
            KDF_SALT_DEFAULT,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
        .expect("argon2");
        let b = derive_key_argon2id(
            b"hunter2",
            KDF_SALT_DEFAULT,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
        .expect("argon2");
        assert_eq!(a, b);
    }

    #[test]
    fn argon2id_differs_from_legacy_sha256() {
        let argon = derive_key_argon2id(
            b"same-pass",
            KDF_SALT_DEFAULT,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
        .expect("argon2");
        let legacy = derive_key_sha256_rounds("same-pass", KDF_SALT_DEFAULT, LEGACY_SHA256_ROUNDS);
        assert_ne!(
            argon, legacy,
            "argon2id and legacy sha256 must produce different keys"
        );
    }

    #[test]
    fn argon2id_changes_with_passphrase() {
        let a = derive_key_argon2id(
            b"alpha",
            KDF_SALT_DEFAULT,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
        .expect("argon2");
        let b = derive_key_argon2id(
            b"beta",
            KDF_SALT_DEFAULT,
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST,
        )
        .expect("argon2");
        assert_ne!(a, b);
    }

    #[test]
    fn argon2id_changes_with_salt() {
        let salt_a = b"salt-aaaaaaaaaaa";
        let salt_b = b"salt-bbbbbbbbbbb";
        let a = derive_key_argon2id(b"same", salt_a, 19_456, 2, 1).expect("argon2");
        let b = derive_key_argon2id(b"same", salt_b, 19_456, 2, 1).expect("argon2");
        assert_ne!(a, b);
    }

    #[test]
    fn argon2id_invalid_params_returns_error() {
        // p_cost = 0 is invalid per RFC 9106.
        let err = derive_key_argon2id(b"x", KDF_SALT_DEFAULT, 19_456, 2, 0).unwrap_err();
        assert!(matches!(err, CryptoError::Argon2Params { p_cost: 0, .. }));
    }

    #[test]
    fn derive_key_dispatches_on_kdf_variant() {
        let argon = derive_key(b"pw", KDF_SALT_DEFAULT, &Kdf::argon2id_default()).expect("argon");
        let legacy = derive_key(b"pw", KDF_SALT_DEFAULT, &Kdf::sha256_legacy()).expect("legacy");
        assert_ne!(argon, legacy);

        // Legacy variant must match the standalone helper for backward compat.
        let legacy_direct = derive_key_sha256_rounds("pw", KDF_SALT_DEFAULT, LEGACY_SHA256_ROUNDS);
        assert_eq!(legacy, legacy_direct);
    }

    #[test]
    fn kdf_default_is_argon2id_owasp_params() {
        let k = Kdf::default();
        match k {
            Kdf::Argon2id {
                m_cost,
                t_cost,
                p_cost,
            } => {
                assert_eq!(m_cost, ARGON2_DEFAULT_M_COST_KIB);
                assert_eq!(t_cost, ARGON2_DEFAULT_T_COST);
                assert_eq!(p_cost, ARGON2_DEFAULT_P_COST);
            }
            other => panic!("default Kdf should be Argon2id, got {other:?}"),
        }
    }

    #[test]
    fn kdf_serde_round_trip_argon2id() {
        let k = Kdf::argon2id_default();
        let json = serde_json::to_string(&k).expect("ser");
        // Tagged repr — `kind: "argon2id"`.
        assert!(json.contains("\"argon2id\""), "json was {json}");
        let back: Kdf = serde_json::from_str(&json).expect("de");
        assert_eq!(k, back);
    }

    #[test]
    fn kdf_serde_round_trip_legacy() {
        let k = Kdf::sha256_legacy();
        let json = serde_json::to_string(&k).expect("ser");
        assert!(json.contains("\"sha256-rounds\""), "json was {json}");
        let back: Kdf = serde_json::from_str(&json).expect("de");
        assert_eq!(k, back);
    }

    #[test]
    fn kdf_from_env_var_accepts_known() {
        assert!(matches!(
            Kdf::from_env_var("argon2id").unwrap(),
            Kdf::Argon2id { .. }
        ));
        assert!(matches!(
            Kdf::from_env_var("sha256-1k").unwrap(),
            Kdf::Sha256Rounds {
                rounds: LEGACY_SHA256_ROUNDS
            }
        ));
        // Default when empty.
        assert!(matches!(
            Kdf::from_env_var("").unwrap(),
            Kdf::Argon2id { .. }
        ));
    }

    #[test]
    fn kdf_from_env_var_rejects_unknown() {
        let err = Kdf::from_env_var("blake3").unwrap_err();
        assert!(matches!(err, CryptoError::KdfUnknown(_)));
    }

    #[test]
    fn encryption_config_from_passphrase_with_kdf_legacy() {
        let cfg = EncryptionConfig::from_passphrase_with_kdf("legacy-pass", Kdf::sha256_legacy())
            .unwrap();
        assert_eq!(cfg.kdf.as_str(), KDF_ID_SHA256_ROUNDS);
        // Backward compat: matches the Phase 16 helper exactly.
        let direct = derive_key_from_passphrase("legacy-pass", KDF_SALT_DEFAULT);
        assert_eq!(cfg.key, direct);
    }

    /// A blob encrypted with the legacy SHA-256 KDF must still decrypt with a
    /// fresh config built from the same passphrase + `Kdf::sha256_legacy()`.
    /// This is the on-disk compatibility guarantee.
    #[test]
    fn legacy_blob_decrypts_under_explicit_legacy_kdf() {
        let cfg_legacy =
            EncryptionConfig::from_passphrase_with_kdf("compat", Kdf::sha256_legacy()).unwrap();
        let blob = encrypt_bytes(b"phase16-style", &cfg_legacy).unwrap();
        // Rebuild the same config from scratch (simulates a fresh process).
        let rebuilt =
            EncryptionConfig::from_passphrase_with_kdf("compat", Kdf::sha256_legacy()).unwrap();
        let plain = decrypt_bytes(&blob, &rebuilt).expect("decrypt under rebuilt legacy cfg");
        assert_eq!(plain, b"phase16-style");
    }

    // Env-var resolution tests share global state — serialise via a Mutex so
    // they don't race when cargo runs them on the default multi-thread pool.
    use std::sync::Mutex;
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        prev_key: Option<String>,
        prev_pass: Option<String>,
        prev_kdf: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl EnvGuard {
        fn new() -> Self {
            let lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
            Self {
                prev_key: std::env::var(ENV_KEY).ok(),
                prev_pass: std::env::var(ENV_PASSPHRASE).ok(),
                prev_kdf: std::env::var(ENV_KDF).ok(),
                _lock: lock,
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev_key.take() {
                Some(v) => std::env::set_var(ENV_KEY, v),
                None => std::env::remove_var(ENV_KEY),
            }
            match self.prev_pass.take() {
                Some(v) => std::env::set_var(ENV_PASSPHRASE, v),
                None => std::env::remove_var(ENV_PASSPHRASE),
            }
            match self.prev_kdf.take() {
                Some(v) => std::env::set_var(ENV_KDF, v),
                None => std::env::remove_var(ENV_KDF),
            }
        }
    }

    #[test]
    fn from_env_explicit_key_path() {
        let _g = EnvGuard::new();
        let raw = base64::engine::general_purpose::STANDARD.encode(fixed_key());
        std::env::set_var(ENV_KEY, &raw);
        std::env::remove_var(ENV_PASSPHRASE);
        std::env::remove_var(ENV_KDF);
        let cfg = EncryptionConfig::from_env().expect("ok").expect("some cfg");
        assert_eq!(cfg.key_source, KeySource::Env);
        assert_eq!(cfg.key, fixed_key());
    }

    #[test]
    fn from_env_passphrase_path_defaults_to_argon2id() {
        let _g = EnvGuard::new();
        std::env::remove_var(ENV_KEY);
        std::env::set_var(ENV_PASSPHRASE, "swordfish");
        std::env::remove_var(ENV_KDF);
        let cfg = EncryptionConfig::from_env().expect("ok").expect("some cfg");
        assert_eq!(cfg.key_source, KeySource::Passphrase);
        assert!(matches!(cfg.kdf, Kdf::Argon2id { .. }));
    }

    #[test]
    fn from_env_passphrase_legacy_kdf_via_env() {
        let _g = EnvGuard::new();
        std::env::remove_var(ENV_KEY);
        std::env::set_var(ENV_PASSPHRASE, "swordfish");
        std::env::set_var(ENV_KDF, "sha256-1k");
        let cfg = EncryptionConfig::from_env().expect("ok").expect("some cfg");
        assert_eq!(cfg.key_source, KeySource::Passphrase);
        match cfg.kdf {
            Kdf::Sha256Rounds { rounds } => assert_eq!(rounds, LEGACY_SHA256_ROUNDS),
            other => panic!("expected Sha256Rounds, got {other:?}"),
        }
        // Backward-compatible: derived key matches the Phase 16 helper.
        assert_eq!(
            cfg.key,
            derive_key_from_passphrase("swordfish", KDF_SALT_DEFAULT)
        );
    }

    #[test]
    fn from_env_returns_none_when_unset() {
        let _g = EnvGuard::new();
        std::env::remove_var(ENV_KEY);
        std::env::remove_var(ENV_PASSPHRASE);
        std::env::remove_var(ENV_KDF);
        let resolved = EncryptionConfig::from_env().expect("ok");
        assert!(resolved.is_none());
    }

    #[test]
    fn from_env_unknown_kdf_propagates_error() {
        let _g = EnvGuard::new();
        std::env::remove_var(ENV_KEY);
        std::env::set_var(ENV_PASSPHRASE, "x");
        std::env::set_var(ENV_KDF, "blake3");
        let err = EncryptionConfig::from_env().unwrap_err();
        assert!(matches!(err, CryptoError::KdfUnknown(_)));
    }
}
