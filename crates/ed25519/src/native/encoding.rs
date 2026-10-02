// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;

/// Validate a canonical prime-subgroup Ed25519 public key and return its bytes.
pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    crate::validate_public_key_identity(pk)?;
    Ok(pk)
}

/// Decode a 32-byte Ed25519 public key, returning it as an owned `Vec`
/// after validating its point encoding.
pub fn decode_public_key(bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_public_key(bytes)?;
    Ok(bytes.to_vec())
}

/// Encode a 32-byte Ed25519 public key, returning it as an owned `Vec`
/// after validating its point encoding.
pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_public_key(pk)?;
    Ok(pk.to_vec())
}
