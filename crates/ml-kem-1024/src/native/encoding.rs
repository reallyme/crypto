// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use ml_kem::ml_kem_1024::EncapsulationKey;

/// Length in bytes of an ML-KEM-1024 encapsulation (public) key.
pub const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1568;

/// Validate that `pubkey` is a well-formed ML-KEM-1024 encapsulation key,
/// returning it unchanged or [`CryptoError::InvalidKey`] otherwise.
pub fn assert_ml_kem_1024_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    let public_key =
        ml_kem::Key::<EncapsulationKey>::try_from(pubkey).map_err(|_| CryptoError::InvalidKey)?;
    EncapsulationKey::new(&public_key).map_err(|_| CryptoError::InvalidKey)?;
    Ok(pubkey)
}

/// Encode an ML-KEM-1024 encapsulation key as an owned `Vec` after validating it.
pub fn encode_ml_kem_1024_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_ml_kem_1024_public_key(pubkey)?.to_vec())
}

/// Decode an ML-KEM-1024 encapsulation key as an owned `Vec` after validating it.
pub fn decode_ml_kem_1024_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_ml_kem_1024_public_key(pubkey)?.to_vec())
}
