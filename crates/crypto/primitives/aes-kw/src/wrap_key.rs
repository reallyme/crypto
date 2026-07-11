// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    types::{key_wrap_error, validate_plaintext_len},
    Aes256KwKek, AesKwWrappedKey, AES_KW_INTEGRITY_CHECK_LENGTH,
};
use aes_kw::{KeyInit, KwAes256};
use crypto_core::{CryptoError, KeyWrapFailureKind, KeyWrapOperation};
use zeroize::Zeroize;

/// Wraps plaintext key material with AES-256-KW (RFC 3394).
pub fn wrap_key(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    validate_plaintext_len(key_data.len())?;
    let wrapped_len = key_data
        .len()
        .checked_add(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or_else(|| {
            key_wrap_error(KeyWrapOperation::Wrap, KeyWrapFailureKind::LengthOverflow)
        })?;
    let mut wrapped = vec![0u8; wrapped_len];
    let kw = KwAes256::new(kek.as_bytes().into());
    let result = kw.wrap_key(key_data, &mut wrapped);
    if result.is_err() {
        wrapped.zeroize();
        return Err(key_wrap_error(
            KeyWrapOperation::Wrap,
            KeyWrapFailureKind::BackendFailure,
        ));
    }

    AesKwWrappedKey::from_slice(&wrapped)
}
