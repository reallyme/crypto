// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

/// Length in bytes of an ML-KEM-512 public key.
pub const ML_KEM_512_PUBLIC_KEY_LEN: usize = 800;
/// Length in bytes of the serialized ML-KEM-512 seed-form secret key.
pub const ML_KEM_512_SECRET_KEY_LEN: usize = 64;

/// Validates an ML-KEM-512 public key and returns the original byte slice.
pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    if pk.len() == ML_KEM_512_PUBLIC_KEY_LEN {
        Ok(pk)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

/// Encodes an ML-KEM-512 public key in raw FIPS 203 form.
pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}

/// Decodes an ML-KEM-512 public key from raw FIPS 203 form.
pub fn decode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}
