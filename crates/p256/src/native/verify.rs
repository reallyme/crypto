// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// verify.rs

use crypto_core::CryptoError;
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;
use sha2::{Digest, Sha256};

/// Verify a DER-encoded P-256 (ES256) ECDSA signature over the SHA-256 hash
/// of `message` under a SEC1-encoded public key.
///
/// Returns `Ok(())` only for a valid signature. Malformed keys/signatures and
/// well-formed signatures that do not verify all fail closed with typed errors.
/// High-S signatures are accepted for ES256 interoperability.
pub fn verify_p256_sha256_message_der_interoperable(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    let pk = PublicKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;

    let vk = VerifyingKey::from(pk);

    let fixed = crate::p256_ecdsa_der_to_jose_signature(signature_der)?;
    let sig = Signature::from_slice(&fixed)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)?;

    // Note: P-256 / ES256 signatures are deliberately NOT constrained to
    // low-S here. Unlike secp256k1, the ES256 ecosystem (JOSE/JWT,
    // WebAuthn, X.509) does not require low-S, and rejecting high-S would
    // break interoperability with conformant signers. ECDSA signatures are
    // therefore not a unique per-message identifier at this layer; callers
    // that need uniqueness must dedup on (message, canonicalized-signature)
    // or use a deterministic scheme.
    if vk.verify_prehash(&Sha256::digest(message), &sig).is_ok() {
        Ok(())
    } else {
        Err(crypto_core::CryptoError::PRIMITIVE_INVALID_SIGNATURE)
    }
}

/// Compatibility name for interoperable P-256/SHA-256 message verification.
#[deprecated(
    since = "0.3.16",
    note = "use verify_p256_sha256_message_der_interoperable; this legacy name accepts message bytes"
)]
pub fn verify_p256_der_prehash(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    verify_p256_sha256_message_der_interoperable(signature_der, message, public_key_sec1)
}
