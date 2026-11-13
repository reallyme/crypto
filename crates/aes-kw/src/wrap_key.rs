// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    types::validate_plaintext_len, Aes128KwKek, Aes192KwKek, Aes256KwKek, AesKwWrappedKey,
    AES_KW_INTEGRITY_CHECK_LENGTH,
};
use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256};
use crypto_core::CryptoError;
use zeroize::Zeroizing;

/// Wraps plaintext key material with AES-256-KW (RFC 3394).
pub fn wrap_key(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    wrap_key_aes256(kek, key_data)
}

/// Wraps plaintext key material with AES-128-KW (RFC 3394).
pub fn wrap_key_aes128(kek: &Aes128KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    let kw = KwAes128::new(kek.as_bytes().into());
    wrap_with(key_data, |output| kw.wrap_key(key_data, output).map(|_| ()))
}

/// Wraps plaintext key material with AES-192-KW (RFC 3394).
pub fn wrap_key_aes192(kek: &Aes192KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    let kw = KwAes192::new(kek.as_bytes().into());
    wrap_with(key_data, |output| kw.wrap_key(key_data, output).map(|_| ()))
}

/// Wraps plaintext key material with AES-256-KW (RFC 3394).
pub fn wrap_key_aes256(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    let kw = KwAes256::new(kek.as_bytes().into());
    wrap_with(key_data, |output| kw.wrap_key(key_data, output).map(|_| ()))
}

fn wrap_with<E>(
    key_data: &[u8],
    wrap: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<AesKwWrappedKey, CryptoError> {
    validate_plaintext_len(key_data.len())?;
    let wrapped_len = key_data
        .len()
        .checked_add(AES_KW_INTEGRITY_CHECK_LENGTH)
        .ok_or(crypto_core::CryptoError::PRIMITIVE_INVALID_LENGTH)?;
    let mut wrapped = Zeroizing::new(vec![0u8; wrapped_len]);
    if wrap(&mut wrapped).is_err() {
        return Err(crypto_core::CryptoError::BACKEND_INTERNAL);
    }

    // Transfer the allocation into its zeroizing owner. This avoids retaining
    // a second wrapped-key copy during boundary-heavy batch operations.
    AesKwWrappedKey::from_zeroizing(wrapped)
}
