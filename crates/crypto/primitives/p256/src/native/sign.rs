// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// sign.rs

use crypto_core::CryptoError;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// Sign with P-256 ECDSA.
///
/// - SHA-256 prehash
/// - DER-encoded signature
pub fn sign_p256_der_prehash(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let sk = SigningKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;

    let digest = Sha256::digest(message);
    let sig: Signature = sk
        .sign_prehash(&digest)
        .map_err(|_| CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Native,
            operation: crypto_core::SignatureOperation::Sign,
            kind: crypto_core::SignatureFailureKind::BackendFailure,
        })?;

    Ok(sig.to_der().as_bytes().to_vec())
}
