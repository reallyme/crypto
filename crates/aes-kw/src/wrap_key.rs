// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    types::{key_wrap_error, validate_plaintext_len},
    Aes128KwKek, Aes192KwKek, Aes256KwKek, AesKwWrappedKey, AES_KW_INTEGRITY_CHECK_LENGTH,
};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use crypto_core::{CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation};
use zeroize::Zeroizing;

/// Wraps plaintext key material with AES-256-KW (RFC 3394).
pub fn wrap_key(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    wrap_key_aes256(kek, key_data)
}

/// Wraps plaintext key material with AES-128-KW (RFC 3394).
pub fn wrap_key_aes128(kek: &Aes128KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    let kw = KwAes128::new(kek.as_bytes().into());
    wrap_with(KeyWrapAlgorithm::Aes128Kw, key_data, |output| {
        kw.wrap_key(key_data, output).map(|_| ())
    })
}

/// Wraps plaintext key material with AES-192-KW (RFC 3394).
pub fn wrap_key_aes192(kek: &Aes192KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    let kw = KwAes192::new(kek.as_bytes().into());
    wrap_with(KeyWrapAlgorithm::Aes192Kw, key_data, |output| {
        kw.wrap_key(key_data, output).map(|_| ())
    })
}

/// Wraps plaintext key material with AES-256-KW (RFC 3394).
pub fn wrap_key_aes256(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    let kw = KwAes256::new(kek.as_bytes().into());
    wrap_with(KeyWrapAlgorithm::Aes256Kw, key_data, |output| {
        kw.wrap_key(key_data, output).map(|_| ())
    })
}

fn wrap_with<E>(
    algorithm: KeyWrapAlgorithm,
    key_data: &[u8],
    wrap: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<AesKwWrappedKey, CryptoError> {
    validate_plaintext_len(algorithm, key_data.len())?;
    let wrapped_len = key_data
        .len()
        .checked_add(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or_else(|| {
            key_wrap_error(
                algorithm,
                KeyWrapOperation::Wrap,
                KeyWrapFailureKind::LengthOverflow,
            )
        })?;
    let mut wrapped = Zeroizing::new(vec![0u8; wrapped_len]);
    if wrap(&mut wrapped).is_err() {
        return Err(key_wrap_error(
            algorithm,
            KeyWrapOperation::Wrap,
            KeyWrapFailureKind::BackendFailure,
        ));
    }

    // Transfer the allocation into its zeroizing owner. This avoids retaining
    // a second wrapped-key copy during boundary-heavy batch operations.
    AesKwWrappedKey::from_zeroizing(algorithm, wrapped)
}
