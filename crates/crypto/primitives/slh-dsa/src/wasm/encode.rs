// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN;
use crypto_core::CryptoError;

/// Encode an SLH-DSA-SHA2-128s public key after validating its length.
pub fn encode_slh_dsa_sha2_128s_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    Ok(public_key.to_vec())
}

/// Decode an SLH-DSA-SHA2-128s public key after validating its length.
pub fn decode_slh_dsa_sha2_128s_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode_slh_dsa_sha2_128s_public_key(public_key)
}
