// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use p521::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::{P521_SECRET_KEY_LEN, P521_SHARED_SECRET_LEN};

/// Derive the raw P-521 ECDH shared secret.
///
/// The returned value is the SEC 1 ECDH x-coordinate. Protocol layers must
/// bind transcript, algorithm, and party context through their own KDF before
/// using this value as symmetric key material.
pub fn derive_p521_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if secret_key.len() != P521_SECRET_KEY_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let secret =
        SecretKey::from_slice(secret_key).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let public =
        PublicKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.raw_secret_bytes();
    if shared_bytes.len() != P521_SHARED_SECRET_LEN {
        return Err(derive_failed());
    }
    if shared_bytes.iter().all(|byte| *byte == 0) {
        return Err(derive_failed());
    }

    Ok(Zeroizing::new(shared_bytes.to_vec()))
}

fn derive_failed() -> CryptoError {
    crypto_core::CryptoError::PRIMITIVE_INVALID_SHARED_SECRET
}
