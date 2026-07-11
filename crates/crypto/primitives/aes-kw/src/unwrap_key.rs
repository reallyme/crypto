// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    types::{key_wrap_error, validate_wrapped_len},
    Aes256KwKek, AesKwKeyData, AES_KW_INTEGRITY_CHECK_LENGTH,
};
use aes_kw::{Error as AesKwError, KeyInit, KwAes256};
use crypto_core::{CryptoError, KeyWrapFailureKind, KeyWrapOperation};
use zeroize::Zeroize;

/// Unwraps RFC 3394 AES-256-KW wrapped key material.
pub fn unwrap_key(kek: &Aes256KwKek, wrapped_key: &[u8]) -> Result<AesKwKeyData, CryptoError> {
    validate_wrapped_len(wrapped_key.len())?;
    let key_data_len = wrapped_key
        .len()
        .checked_sub(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or_else(|| {
            key_wrap_error(
                KeyWrapOperation::Unwrap,
                KeyWrapFailureKind::InvalidWrappedLength,
            )
        })?;
    let mut key_data = vec![0u8; key_data_len];
    let kw = KwAes256::new(kek.as_bytes().into());
    match kw.unwrap_key(wrapped_key, &mut key_data) {
        Ok(_) => {
            // Copy into the zeroizing owner, then wipe this transient plaintext
            // buffer. The unwrapped key is the exact material AES-KW protects.
            // The error arms already zeroize; keep the success path symmetric.
            let result = AesKwKeyData::from_slice(&key_data);
            key_data.zeroize();
            result
        }
        Err(AesKwError::IntegrityCheckFailed) => {
            key_data.zeroize();
            Err(key_wrap_error(
                KeyWrapOperation::Unwrap,
                KeyWrapFailureKind::IntegrityCheckFailed,
            ))
        }
        Err(_) => {
            key_data.zeroize();
            Err(key_wrap_error(
                KeyWrapOperation::Unwrap,
                KeyWrapFailureKind::BackendFailure,
            ))
        }
    }
}
