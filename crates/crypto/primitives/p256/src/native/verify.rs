// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// verify.rs

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
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
pub fn verify_p256_der_prehash(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    let pk = PublicKey::from_sec1_bytes(public_key_sec1).map_err(|_| CryptoError::InvalidKey)?;

    let vk = VerifyingKey::from(pk);

    let sig = Signature::from_der(signature_der).map_err(|_| CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Native,
        operation: crypto_core::SignatureOperation::Verify,
        kind: crypto_core::SignatureFailureKind::InvalidSignature,
    })?;

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
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
