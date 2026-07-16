// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

/// Length in bytes of an ML-DSA-65 public key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Validates an ML-DSA-65 public key and returns the original byte slice.
pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    if pk.len() == ML_DSA_65_PUBLIC_KEY_LEN {
        Ok(pk)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

/// Encodes an ML-DSA-65 public key in raw FIPS 204 form.
pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}

/// Decodes an ML-DSA-65 public key from raw FIPS 204 form.
pub fn decode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}
