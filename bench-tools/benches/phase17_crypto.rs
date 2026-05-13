//! Phase 17 — crypto hardening benches.
//!
//! Measured paths:
//!   1. argon2id KDF (m_cost 19_456 KiB / t_cost 2 / p_cost 1) — the
//!      hardened replacement for the Phase 16 1000-round SHA-256 KDF.
//!   2. AES-256-GCM encrypt + decrypt at 1 MiB / 10 MiB / 100 MiB blob sizes.
//!   3. Legacy SHA-256(1000-round) vs argon2id side-by-side so the cost
//!      delta of the upgrade is visible on every CI bench run.
//!
//! The harness is workspace-level on purpose — it must not depend on
//! `linpodx-runtime` internals so Stream A can refactor `snapshot_crypto`
//! freely without breaking the bench.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

// ----- argon2id KDF (the Phase 17 replacement for Sha256Rounds(1000)). -----

/// Parameters chosen to match `linpodx-runtime` Stream A:
///   * m_cost = 19_456 KiB (~19 MB working set)
///   * t_cost = 2 iterations
///   * p_cost = 1 lane
fn argon2id_kdf(passphrase: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN)).expect("argon2 params");
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    kdf.hash_password_into(passphrase, salt, &mut out)
        .expect("argon2id hash");
    out
}

fn bench_argon2id_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("phase17/kdf");
    group.sample_size(10); // KDF is intentionally slow.
    let salt: &[u8; 16] = b"linpodx-snap/v1.";
    group.bench_function("argon2id_m19456_t2_p1", |b| {
        b.iter(|| argon2id_kdf(black_box(b"hunter2-correct-horse"), black_box(salt)))
    });
    group.finish();
}

// ----- Legacy KDF (Sha256Rounds(1000)) for the comparison graph. -----

fn sha256_rounds_kdf(passphrase: &[u8], salt: &[u8; 16]) -> [u8; KEY_LEN] {
    let mut state = [0u8; KEY_LEN];
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(passphrase);
    state.copy_from_slice(&hasher.finalize());
    for round in 1u32..1000 {
        let mut h = Sha256::new();
        h.update(state);
        h.update(round.to_be_bytes());
        h.update(salt);
        state.copy_from_slice(&h.finalize());
    }
    state
}

fn bench_kdf_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("phase17/kdf_comparison");
    group.sample_size(10);
    let salt: &[u8; 16] = b"linpodx-snap/v1.";
    group.bench_function("legacy_sha256_rounds_1000", |b| {
        b.iter(|| sha256_rounds_kdf(black_box(b"hunter2-correct-horse"), black_box(salt)))
    });
    group.bench_function("phase17_argon2id_m19456_t2_p1", |b| {
        b.iter(|| argon2id_kdf(black_box(b"hunter2-correct-horse"), black_box(salt)))
    });
    group.finish();
}

// ----- AES-256-GCM throughput at 1MB / 10MB / 100MB. -----

fn random_blob(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    OsRng.fill_bytes(&mut v);
    v
}

fn encrypt(cipher: &Aes256Gcm, plain: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plain).expect("encrypt");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

fn decrypt(cipher: &Aes256Gcm, blob: &[u8]) -> Vec<u8> {
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).expect("decrypt")
}

fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("phase17/aes_gcm");
    group.sample_size(10); // 100 MiB encrypt is slow.

    let key = [0u8; KEY_LEN];
    let cipher = Aes256Gcm::new((&key).into());

    // Cover the snapshot-blob size distribution seen in practice.
    // 1 MiB = small overlayfs layer; 100 MiB = full container rootfs side-car.
    let sizes = [
        ("1mb", 1024 * 1024usize),
        ("10mb", 10 * 1024 * 1024usize),
        ("100mb", 100 * 1024 * 1024usize),
    ];

    for (label, size) in sizes.iter().copied() {
        let plain = random_blob(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", label), &plain, |b, plain| {
            b.iter(|| encrypt(black_box(&cipher), black_box(plain)))
        });
        let blob = encrypt(&cipher, &plain);
        group.bench_with_input(BenchmarkId::new("decrypt", label), &blob, |b, blob| {
            b.iter(|| decrypt(black_box(&cipher), black_box(blob)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_argon2id_kdf,
    bench_kdf_comparison,
    bench_aes_gcm
);
criterion_main!(benches);
