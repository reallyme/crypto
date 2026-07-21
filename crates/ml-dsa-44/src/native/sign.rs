// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use ml_dsa::{MlDsa44, Seed, SignatureEncoding, Signer, SigningKey};
use zeroize::Zeroizing;

/// Sign a message using ML-DSA-44.
///
/// - `priv_bytes` MUST be exactly 32 seed bytes
/// - Raw message, no hashing, no context
pub fn sign_ml_dsa_44(priv_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Keep the stack copy of the seed in a zeroizing wrapper so it is wiped
    // when signing completes.
    let seed = Zeroizing::new(Seed::try_from(priv_bytes).map_err(|_| CryptoError::InvalidKey)?);
    let signing_key = SigningKey::<MlDsa44>::from_seed(&seed);
    let sig = signing_key
        .try_sign(msg)
        .map_err(|_| CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Native,
            operation: crypto_core::SignatureOperation::Sign,
            kind: crypto_core::SignatureFailureKind::BackendFailure,
        })?;

    Ok(sig.to_bytes().to_vec())
}
