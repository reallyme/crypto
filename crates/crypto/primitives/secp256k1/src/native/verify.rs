// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// verify.rs

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::PublicKey;
use sha2::{Digest, Sha256};

/// Verifies a 64-byte compact secp256k1 ECDSA signature over `message`.
///
/// The public API accepts the original message, hashes it exactly once with
/// SHA-256, and verifies the supplied compact `r || s` signature against that
/// digest. Use the prehash trait here deliberately: k256's high-level
/// `Verifier` hashes its input as a message, which would otherwise verify
/// SHA-256(SHA-256(message)).
///
/// Returns `Ok(())` only for a valid signature. Malformed keys/signatures and
/// well-formed signatures that do not verify all fail closed with typed errors.
/// Enforces low-S (BIP-0062), rejecting the malleated high-S twin.
pub fn verify_secp256k1(
    signature: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != 64 {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Native,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    let pk = PublicKey::from_sec1_bytes(public_key_sec1).map_err(|_| CryptoError::InvalidKey)?;

    let vk = VerifyingKey::from(pk);

    let sig = Signature::try_from(signature).map_err(|_| CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Native,
        operation: crypto_core::SignatureOperation::Verify,
        kind: crypto_core::SignatureFailureKind::InvalidSignature,
    })?;

    // Enforce low-S (BIP 0062): reject the malleated high-S twin so a
    // signature has a single canonical encoding. Signing already
    // normalizes to low-S, so signatures produced by this crate pass; this only
    // rejects the second, equally valid (r, n-s) form that would otherwise
    // let one message carry two distinct verifying signatures.
    if sig.normalize_s() != sig {
        return Err(CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Native,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        });
    }

    if vk
        .verify_prehash(Sha256::digest(message).as_ref(), &sig)
        .is_ok()
    {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
