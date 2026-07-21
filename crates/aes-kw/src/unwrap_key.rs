// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    types::{key_wrap_error, validate_wrapped_len},
    Aes128KwKek, Aes192KwKek, Aes256KwKek, AesKwKeyData, AES_KW_INTEGRITY_CHECK_LENGTH,
};
use aes_kw::{Error as AesKwError, KeyInit, KwAes128, KwAes192, KwAes256};
use crypto_core::{CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation};
use zeroize::Zeroizing;

/// Unwraps RFC 3394 AES-256-KW wrapped key material.
pub fn unwrap_key(kek: &Aes256KwKek, wrapped_key: &[u8]) -> Result<AesKwKeyData, CryptoError> {
    unwrap_key_aes256(kek, wrapped_key)
}

/// Unwraps RFC 3394 AES-128-KW wrapped key material.
pub fn unwrap_key_aes128(
    kek: &Aes128KwKek,
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    let kw = KwAes128::new(kek.as_bytes().into());
    unwrap_with(KeyWrapAlgorithm::Aes128Kw, wrapped_key, |output| {
        kw.unwrap_key(wrapped_key, output).map(|_| ())
    })
}

/// Unwraps RFC 3394 AES-192-KW wrapped key material.
pub fn unwrap_key_aes192(
    kek: &Aes192KwKek,
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    let kw = KwAes192::new(kek.as_bytes().into());
    unwrap_with(KeyWrapAlgorithm::Aes192Kw, wrapped_key, |output| {
        kw.unwrap_key(wrapped_key, output).map(|_| ())
    })
}

/// Unwraps RFC 3394 AES-256-KW wrapped key material.
pub fn unwrap_key_aes256(
    kek: &Aes256KwKek,
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    let kw = KwAes256::new(kek.as_bytes().into());
    unwrap_with(KeyWrapAlgorithm::Aes256Kw, wrapped_key, |output| {
        kw.unwrap_key(wrapped_key, output).map(|_| ())
    })
}

fn unwrap_with(
    algorithm: KeyWrapAlgorithm,
    wrapped_key: &[u8],
    unwrap: impl FnOnce(&mut [u8]) -> Result<(), AesKwError>,
) -> Result<AesKwKeyData, CryptoError> {
    validate_wrapped_len(algorithm, wrapped_key.len())?;
    let key_data_len = wrapped_key
        .len()
        .checked_sub(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or_else(|| {
            key_wrap_error(
                algorithm,
                KeyWrapOperation::Unwrap,
                KeyWrapFailureKind::InvalidWrappedLength,
            )
        })?;
    let mut key_data = Zeroizing::new(vec![0u8; key_data_len]);
    match unwrap(&mut key_data) {
        // Transfer the plaintext allocation directly into its final owner so
        // no second heap copy of the unwrapped key exists on the success path.
        Ok(_) => AesKwKeyData::from_zeroizing(algorithm, key_data),
        Err(AesKwError::IntegrityCheckFailed) => Err(key_wrap_error(
            algorithm,
            KeyWrapOperation::Unwrap,
            KeyWrapFailureKind::IntegrityCheckFailed,
        )),
        Err(_) => Err(key_wrap_error(
            algorithm,
            KeyWrapOperation::Unwrap,
            KeyWrapFailureKind::BackendFailure,
        )),
    }
}
