// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KeyAgreementFailureKind};
use p384::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::{P384_SECRET_KEY_LEN, P384_SHARED_SECRET_LEN};

/// Derive the raw P-384 ECDH shared secret.
///
/// The returned value is the SEC 1 ECDH x-coordinate. Protocol layers must
/// bind transcript, algorithm, and party context through their own KDF before
/// using this value as symmetric key material.
pub fn derive_p384_shared_secret(
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if secret_key.len() != P384_SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }

    let secret = SecretKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;
    let public = PublicKey::from_sec1_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.raw_secret_bytes();
    if shared_bytes.len() != P384_SHARED_SECRET_LEN {
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
