// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KeyAgreementFailureKind};

use crate::{X448PrivateKey, X448PublicKey, X448SharedSecret};

/// Derives a raw X448 shared secret without applying a KDF.
///
/// `X448PublicKey` construction rejects low-order points before this operation,
/// preventing agreement on a non-contributory, world-known value.
pub fn derive_x448_shared_secret(
    private_key: &X448PrivateKey,
    public_key: X448PublicKey,
) -> Result<X448SharedSecret, CryptoError> {
    let backend_public_key = public_key.backend()?;
    let shared_secret = private_key.backend().diffie_hellman(&backend_public_key);
    if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CryptoError::KeyAgreementFailure {
            kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
        });
    }
    Ok(X448SharedSecret::from_array(*shared_secret.as_bytes()))
}
