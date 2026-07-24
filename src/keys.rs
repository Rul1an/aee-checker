//! Deterministic test-key derivation per the conformance suite's published
//! recipe (vectors/keys/README.md):
//!
//!     seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")
//!
//! The public key is the Ed25519 public key for that seed. These keys are
//! test-only material; the checker pins the substrate observation role out
//! of band, exactly as a consumer's key policy would.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn derive_verifying_key(role: &str) -> VerifyingKey {
    let seed: [u8; 32] = Sha256::digest(format!("in-toto-aee-test-key/{role}/v1")).into();
    SigningKey::from_bytes(&seed).verifying_key()
}

pub fn verify(key: &VerifyingKey, message: &[u8], sig_bytes: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(sig_bytes) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}
