// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// encoding.rs

use crypto_core::CryptoError;

/// Length in bytes of an ML-DSA-44 public key.
pub const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
/// Length in bytes of the ML-DSA-44 secret key seed.
pub const ML_DSA_44_SECRET_SEED_LEN: usize = 32;
/// Length in bytes of an ML-DSA-44 signature.
pub const ML_DSA_44_SIGNATURE_LEN: usize = 2420;

/// Validate that `pk` has the ML-DSA-44 public-key length, returning it
/// unchanged or [`CryptoError::InvalidKey`] otherwise.
pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    if pk.len() == ML_DSA_44_PUBLIC_KEY_LEN {
        Ok(pk)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

/// Encode an ML-DSA-44 public key as an owned `Vec` after validating its length.
pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}

/// Decode an ML-DSA-44 public key as an owned `Vec` after validating its length.
pub fn decode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}
