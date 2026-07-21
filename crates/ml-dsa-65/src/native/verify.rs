// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};

/// Verify an ML-DSA-65 detached signature.
///
/// - `pub_bytes` MUST be exactly 1952 bytes
/// - `sig_bytes` MUST be exactly 3309 bytes
/// - Raw message, no hashing, no context
pub fn verify_ml_dsa_65(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), CryptoError> {
    let public_key =
        EncodedVerifyingKey::<MlDsa65>::try_from(pub_bytes).map_err(|_| CryptoError::InvalidKey)?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&public_key);
    let sig = Signature::<MlDsa65>::try_from(sig_bytes).map_err(|_| CryptoError::Signature {
        backend: crypto_core::SignatureBackend::Native,
        operation: crypto_core::SignatureOperation::Verify,
        kind: crypto_core::SignatureFailureKind::InvalidSignature,
    })?;

    if verifying_key.verify(msg, &sig).is_ok() {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
