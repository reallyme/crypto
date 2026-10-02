// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};

const ED25519_POINT_LENGTH: usize = 32;

/// Strictly verify an Ed25519 signature over `message` under `public`.
///
/// Returns `Ok(())` only for a valid signature. Malformed public keys and
/// structurally invalid signatures return typed errors; well-formed signatures
/// that do not verify fail closed with the same invalid-signature variant.
pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let pubkey: &[u8; ED25519_POINT_LENGTH] =
        public.try_into().map_err(|_| CryptoError::InvalidKey)?;

    let public_point = CompressedEdwardsY(*pubkey)
        .decompress()
        .ok_or_else(invalid_signature)?;
    if !crate::validate_public_key::is_canonical_point_encoding(&public_point, pubkey) {
        return Err(invalid_signature());
    }
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| invalid_signature())?;

    let sig_bytes: &[u8; 64] = signature.try_into().map_err(|_| CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Native,
        operation: crypto_core::SignatureOperation::Verify,
        kind: crypto_core::SignatureFailureKind::InvalidSignature,
    })?;

    let sig = Signature::from_bytes(sig_bytes);
    let mut r_bytes = [0_u8; ED25519_POINT_LENGTH];
    r_bytes.copy_from_slice(&sig_bytes[..ED25519_POINT_LENGTH]);
    let r_point = CompressedEdwardsY(r_bytes)
        .decompress()
        .ok_or_else(invalid_signature)?;

    // Require prime-subgroup points in every provider lane. This rules out
    // mixed-order encodings that can pass a cofactored verification equation.
    if !public_point.is_torsion_free() || !r_point.is_torsion_free() {
        return Err(invalid_signature());
    }

    // `verify_strict` rejects signature malleability and small-order /
    // non-canonical public keys, matching the strict verification the rest
    // of the ecosystem (and the conformance oracle) use. The permissive
    // `verify` would accept variant encodings that must not count as valid
    // for an identity signature.
    if vk.verify_strict(message, &sig).is_ok() {
        Ok(())
    } else {
        Err(invalid_signature())
    }
}

fn invalid_signature() -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    }
}
