// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KemFailureKind};
use zeroize::Zeroizing;

use crate::suite::{
    ML_KEM_SHARED_SECRET_LEN, X25519_KEY_LEN, X_WING_LABEL, X_WING_SHARED_SECRET_LEN,
};

fn combiner_capacity() -> Result<usize, CryptoError> {
    ML_KEM_SHARED_SECRET_LEN
        .checked_add(X25519_KEY_LEN)
        .and_then(|value| value.checked_add(X25519_KEY_LEN))
        .and_then(|value| value.checked_add(X25519_KEY_LEN))
        .and_then(|value| value.checked_add(X_WING_LABEL.len()))
        .ok_or(CryptoError::KemFailure {
            kind: KemFailureKind::EncapsulateFailed,
        })
}

pub(crate) fn combine_shared_secret(
    ml_kem_shared_secret: &[u8],
    x25519_shared_secret: &[u8; X25519_KEY_LEN],
    x25519_ciphertext: &[u8; X25519_KEY_LEN],
    x25519_public_key: &[u8; X25519_KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ml_kem_shared_secret.len() != ML_KEM_SHARED_SECRET_LEN {
        return Err(CryptoError::KemFailure {
            kind: KemFailureKind::EncapsulateFailed,
        });
    }

    let mut input = Zeroizing::new(Vec::with_capacity(combiner_capacity()?));
    input.extend_from_slice(ml_kem_shared_secret);
    input.extend_from_slice(x25519_shared_secret);
    input.extend_from_slice(x25519_ciphertext);
    input.extend_from_slice(x25519_public_key);
    input.extend_from_slice(X_WING_LABEL);

    let digest = crypto_sha3_256::digest(input.as_slice());
    let shared_secret = Zeroizing::new(digest.as_bytes().to_vec());

    debug_assert_eq!(shared_secret.len(), X_WING_SHARED_SECRET_LEN);
    Ok(shared_secret)
}
