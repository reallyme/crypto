// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;

pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
pub const ML_KEM_768_SECRET_KEY_LEN: usize = 64;

pub fn assert_public_key(pk: &[u8]) -> Result<&[u8], CryptoError> {
    if pk.len() == ML_KEM_768_PUBLIC_KEY_LEN {
        Ok(pk)
    } else {
        Err(CryptoError::InvalidKey)
    }
}

pub fn encode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}

pub fn decode_public_key(pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(assert_public_key(pk)?.to_vec())
}
