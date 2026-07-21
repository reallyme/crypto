// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ed25519_dalek::{Signature, VerifyingKey};

/// Strictly verify an Ed25519 signature over `message` under `public`.
///
/// Returns `Ok(())` only for a valid signature. Malformed public keys and
/// structurally invalid signatures return typed errors; well-formed signatures
/// that do not verify fail closed with the same invalid-signature variant.
pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let pubkey: &[u8; 32] = public.try_into().map_err(|_| CryptoError::InvalidKey)?;

    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| CryptoError::InvalidKey)?;

    let sig_bytes: &[u8; 64] = signature.try_into().map_err(|_| CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Native,
        operation: crypto_core::SignatureOperation::Verify,
        kind: crypto_core::SignatureFailureKind::InvalidSignature,
    })?;

    let sig = Signature::from_bytes(sig_bytes);

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
