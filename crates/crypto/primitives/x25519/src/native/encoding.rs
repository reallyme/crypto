// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

/// Validate that a value is a 32-byte X25519 public key.
pub fn assert_public_key(pubkey: &[u8]) -> Result<&[u8], CryptoError> {
    if pubkey.len() == 32 {
        Ok(pubkey)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

/// Identity encoder.
pub fn encode_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pubkey)?.to_vec())
}

/// Identity decoder.
pub fn decode_public_key(pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pubkey)?.to_vec())
}
