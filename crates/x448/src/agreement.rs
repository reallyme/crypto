// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use subtle::ConstantTimeEq;

use crate::{X448PrivateKey, X448PublicKey, X448SharedSecret, X448_SHARED_SECRET_LEN};

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
    release_shared_secret(shared_secret.as_bytes())
}

fn release_shared_secret(
    bytes: &[u8; X448_SHARED_SECRET_LEN],
) -> Result<X448SharedSecret, CryptoError> {
    if bool::from(bytes.ct_eq(&[0_u8; X448_SHARED_SECRET_LEN])) {
        return Err(CryptoError::PRIMITIVE_INVALID_SHARED_SECRET);
    }
    Ok(X448SharedSecret::from_array(*bytes))
}

#[cfg(kani)]
#[path = "agreement/proof_tests.rs"]
mod proof_tests;
