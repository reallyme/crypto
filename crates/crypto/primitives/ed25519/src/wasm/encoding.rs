// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

/// Validates an Ed25519 public key and returns the original byte slice.
pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    if pk.len() == 32 {
        Ok(pk)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

/// Encodes an Ed25519 public key in the canonical raw 32-byte form.
pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_public_key(pk)?;
    Ok(pk.to_vec())
}

/// Decodes an Ed25519 public key from the canonical raw 32-byte form.
pub fn decode_public_key(bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_public_key(bytes)?;
    Ok(bytes.to_vec())
}
