// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    if pk.len() == 32 {
        Ok(pk)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_public_key(pk)?;
    Ok(pk.to_vec())
}

pub fn decode_public_key(bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert_public_key(bytes)?;
    Ok(bytes.to_vec())
}
