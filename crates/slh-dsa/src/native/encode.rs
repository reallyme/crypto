// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN;
use crypto_core::CryptoError;
use slh_dsa::{Sha2_128s, VerifyingKey};

fn validate_slh_dsa_sha2_128s_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKey);
    }
    VerifyingKey::<Sha2_128s>::try_from(public_key).map_err(|_| CryptoError::InvalidKey)?;
    Ok(())
}

/// Encode an SLH-DSA-SHA2-128s public key after validating its canonical shape.
pub fn encode_slh_dsa_sha2_128s_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_slh_dsa_sha2_128s_public_key(public_key)?;
    Ok(public_key.to_vec())
}

/// Decode an SLH-DSA-SHA2-128s public key after validating its canonical shape.
pub fn decode_slh_dsa_sha2_128s_public_key(public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_slh_dsa_sha2_128s_public_key(public_key)?;
    Ok(public_key.to_vec())
}
