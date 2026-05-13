//! ed25519 plugin signature verification (Phase 15).
//!
//! The sandbox install path calls [`verify_plugin_signature`] before persisting a wasm
//! binary to the on-disk plugin store. The signature must be a raw 64-byte ed25519
//! signature, base64-encoded (standard alphabet, padding optional). The public key is a
//! PEM-encoded `SubjectPublicKeyInfo` (X.509) or PKCS#8, parsed via ed25519-dalek's
//! `pkcs8`/`pem` features (both enabled in the workspace dep).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    #[error("public key PEM parse failed: {0}")]
    KeyParse(String),
    #[error("signature base64 decode failed: {0}")]
    SignatureDecode(String),
    #[error("signature must be exactly {expected} bytes, got {actual}")]
    SignatureLength { expected: usize, actual: usize },
    #[error("signature verification failed: {0}")]
    VerifyFailed(String),
}

/// Verify a detached ed25519 signature over `wasm_bytes`.
///
/// * `signature_b64` — base64 (standard alphabet) of the raw 64-byte signature.
/// * `public_key_pem` — PEM-encoded SubjectPublicKeyInfo for an Ed25519 key.
///
/// Uses [`VerifyingKey::verify_strict`] which rejects malleable/non-canonical signature
/// encodings (the safer of the two ed25519-dalek 2 verification modes).
pub fn verify_plugin_signature(
    wasm_bytes: &[u8],
    signature_b64: &str,
    public_key_pem: &str,
) -> Result<(), SigningError> {
    let key = VerifyingKey::from_public_key_pem(public_key_pem.trim())
        .map_err(|e| SigningError::KeyParse(e.to_string()))?;

    let raw = B64
        .decode(signature_b64.trim().as_bytes())
        .map_err(|e| SigningError::SignatureDecode(e.to_string()))?;
    if raw.len() != SIGNATURE_LENGTH {
        return Err(SigningError::SignatureLength {
            expected: SIGNATURE_LENGTH,
            actual: raw.len(),
        });
    }
    let mut sig_bytes = [0u8; SIGNATURE_LENGTH];
    sig_bytes.copy_from_slice(&raw);
    let sig = Signature::from_bytes(&sig_bytes);

    key.verify_strict(wasm_bytes, &sig)
        .map_err(|e| SigningError::VerifyFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_signing_key() -> SigningKey {
        // Deterministic 32-byte seed → reproducible test keypair.
        let seed: [u8; 32] = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn pem_for(key: &SigningKey) -> String {
        key.verifying_key()
            .to_public_key_pem(Default::default())
            .expect("encode pem")
    }

    fn b64_sign(key: &SigningKey, msg: &[u8]) -> String {
        let sig: Signature = key.sign(msg);
        B64.encode(sig.to_bytes())
    }

    #[test]
    fn verify_succeeds_for_valid_signature() {
        let key = fixed_signing_key();
        let msg = b"hello plugin world";
        let sig = b64_sign(&key, msg);
        verify_plugin_signature(msg, &sig, &pem_for(&key)).expect("verify ok");
    }

    #[test]
    fn verify_fails_for_tampered_message() {
        let key = fixed_signing_key();
        let sig = b64_sign(&key, b"original");
        let err = verify_plugin_signature(b"tampered", &sig, &pem_for(&key)).unwrap_err();
        assert!(matches!(err, SigningError::VerifyFailed(_)));
    }

    #[test]
    fn verify_fails_for_wrong_key() {
        let signer = fixed_signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let msg = b"plugin bytes";
        let sig = b64_sign(&signer, msg);
        let err = verify_plugin_signature(msg, &sig, &pem_for(&other)).unwrap_err();
        assert!(matches!(err, SigningError::VerifyFailed(_)));
    }

    #[test]
    fn verify_rejects_non_base64() {
        let key = fixed_signing_key();
        let err = verify_plugin_signature(b"x", "!!!not base64!!!", &pem_for(&key)).unwrap_err();
        assert!(matches!(err, SigningError::SignatureDecode(_)));
    }

    #[test]
    fn verify_rejects_short_signature() {
        let key = fixed_signing_key();
        // 16 bytes of zeros → base64 of 16 bytes is 24 chars, not 64.
        let bad = B64.encode([0u8; 16]);
        let err = verify_plugin_signature(b"x", &bad, &pem_for(&key)).unwrap_err();
        assert!(matches!(
            err,
            SigningError::SignatureLength {
                expected: 64,
                actual: 16
            }
        ));
    }

    /// End-to-end check against the checked-in `examples/plugins/signed-noop/`
    /// artifacts. If anyone re-signs the example, this test enforces the fixture stays
    /// consistent (signature matches the wasm bytes under the test pub key).
    #[test]
    fn verify_succeeds_against_signed_noop_example() {
        let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("examples")
            .join("plugins")
            .join("signed-noop");
        let wasm = std::fs::read(example.join("noop.wasm")).expect("read noop.wasm");
        let sig = std::fs::read_to_string(example.join("signature.b64")).expect("read sig");
        let pem = std::fs::read_to_string(example.join("test.pub")).expect("read pem");
        verify_plugin_signature(&wasm, sig.trim(), &pem).expect("example signature must verify");
    }

    #[test]
    fn verify_rejects_garbage_pem() {
        let key = fixed_signing_key();
        let sig = b64_sign(&key, b"x");
        let err = verify_plugin_signature(
            b"x",
            &sig,
            "-----BEGIN PUBLIC KEY-----\nxx\n-----END PUBLIC KEY-----",
        )
        .unwrap_err();
        assert!(matches!(err, SigningError::KeyParse(_)));
    }
}
