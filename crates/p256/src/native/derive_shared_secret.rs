// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KeyAgreementFailureKind};
use p256::{PublicKey, SecretKey};
use zeroize::Zeroizing;

const P256_SECRET_KEY_LEN: usize = 32;
const P256_SHARED_SECRET_LEN: usize = 32;

/// Derive the raw P-256 ECDH shared secret.
///
/// The returned value is the SEC 1 ECDH x-coordinate. It is intentionally not
/// passed through a KDF here because HPKE, JOSE, COSE, TLS, and MLS each bind
/// different transcript and algorithm context into their own extract/expand
/// step. Protocol crates must domain-separate this value before using it as
/// symmetric key material.
pub fn derive_p256_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if secret_key.len() != P256_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let secret = SecretKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let public = PublicKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.raw_secret_bytes();
    if shared_bytes.len() != P256_SHARED_SECRET_LEN {
        return Err(derive_failed());
    }
    if shared_bytes.iter().all(|byte| *byte == 0) {
        return Err(derive_failed());
    }

    Ok(Zeroizing::new(shared_bytes.to_vec()))
}

fn derive_failed() -> CryptoError {
    CryptoError::KeyAgreementFailure {
        kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
    }
}
