// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use ml_kem::ml_kem_768::EncapsulationKey;

/// Length in bytes of an ML-KEM-768 encapsulation (public) key.
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize =
    crypto_core::contract_constants::ml_kem_768::ML_KEM_768_PUBLIC_KEY_LEN;

/// Validate that `pubkey` is a well-formed ML-KEM-768 encapsulation key,
/// returning it unchanged or [`CryptoError::PRIMITIVE_INVALID_KEY`] otherwise.
pub fn assert_ml_kem_768_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    let public_key = ml_kem::Key::<EncapsulationKey>::try_from(pubkey)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    EncapsulationKey::new(&public_key).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    Ok(pubkey)
}

/// Encode an ML-KEM-768 encapsulation key as an owned `Vec` after validating it.
pub fn encode_ml_kem_768_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_ml_kem_768_public_key(pubkey)?.to_vec())
}

/// Decode an ML-KEM-768 encapsulation key as an owned `Vec` after validating it.
pub fn decode_ml_kem_768_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_ml_kem_768_public_key(pubkey)?.to_vec())
}
