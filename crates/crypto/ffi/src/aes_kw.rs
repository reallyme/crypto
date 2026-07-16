// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_output_len_pair, write_fixed, write_len};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_aes_kw::{
    unwrap_key, wrap_key, Aes256KwKek, AES_256_KW_KEK_LENGTH, AES_KW_BLOCK_LENGTH,
    AES_KW_INTEGRITY_CHECK_LENGTH, AES_KW_MAX_KEY_DATA_LENGTH, AES_KW_MIN_KEY_DATA_LENGTH,
    AES_KW_MIN_WRAPPED_KEY_LENGTH,
};
use crypto_core::{CryptoError, KeyWrapFailureKind};
use zeroize::Zeroize;

/// Length in bytes of an AES-256-KW key-encryption key (32).
pub const AES256_KW_KEK_LEN: usize = AES_256_KW_KEK_LENGTH;
/// RFC 3394 AES-KW block length in bytes (8).
pub const AES_KW_BLOCK_LEN: usize = AES_KW_BLOCK_LENGTH;
/// RFC 3394 AES-KW integrity-check length in bytes (8).
pub const AES_KW_INTEGRITY_LEN: usize = AES_KW_INTEGRITY_CHECK_LENGTH;
/// Minimum plaintext key-data length accepted by AES-KW (16).
pub const AES_KW_MIN_KEY_DATA_LEN: usize = AES_KW_MIN_KEY_DATA_LENGTH;
/// Minimum wrapped key-data length accepted by AES-KW (24).
pub const AES_KW_MIN_WRAPPED_KEY_LEN: usize = AES_KW_MIN_WRAPPED_KEY_LENGTH;
/// Maximum plaintext key-data length accepted by this ABI.
pub const AES_KW_MAX_KEY_DATA_LEN: usize = AES_KW_MAX_KEY_DATA_LENGTH;

fn map_wrap_error(error: CryptoError) -> CryptoStatus {
    match error {
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::InvalidKekLength,
            ..
        } => CRYPTO_INVALID_KEY,
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::InvalidPlaintextLength | KeyWrapFailureKind::LengthOverflow,
            ..
        } => CRYPTO_INVALID_ARGUMENT,
        _ => CRYPTO_INVALID_CIPHERTEXT,
    }
}

fn map_unwrap_error(error: CryptoError) -> CryptoStatus {
    match error {
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::InvalidKekLength,
            ..
        } => CRYPTO_INVALID_KEY,
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::IntegrityCheckFailed,
            ..
        } => CRYPTO_AUTHENTICATION_FAILED,
        _ => CRYPTO_INVALID_CIPHERTEXT,
    }
}

/// Wraps plaintext key material with AES-256-KW (RFC 3394).
///
/// # Safety
///
/// `kek` must be valid for `kek_len` bytes (must be 32), and `key_data` must
/// be valid for `key_data_len` bytes. `wrapped_out` must point to at least
/// `wrapped_out_len` writable bytes, and `wrapped_len_out` must be a non-null
/// writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes256_kw_wrap_key(
    kek: *const u8,
    kek_len: usize,
    key_data: *const u8,
    key_data_len: usize,
    wrapped_out: *mut u8,
    wrapped_out_len: usize,
    wrapped_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status = validate_output_len_pair(wrapped_out, wrapped_out_len, wrapped_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let kek = match unsafe { read_slice(kek, kek_len) } {
            Ok(value) => match Aes256KwKek::from_slice(value) {
                Ok(kek) => kek,
                Err(error) => return map_wrap_error(error),
            },
            Err(status) => return status,
        };
        let key_data = match unsafe { read_slice(key_data, key_data_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let expected_len = match key_data.len().checked_add(AES_KW_INTEGRITY_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if wrapped_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let mut wrapped = match wrap_key(&kek, key_data) {
            Ok(value) => value.into_vec(),
            Err(error) => return map_wrap_error(error),
        };
        let status = unsafe { write_fixed(wrapped_out, wrapped_out_len, &wrapped) };
        if status != CRYPTO_OK {
            wrapped.zeroize();
            return status;
        }
        let status = unsafe { write_len(wrapped_len_out, wrapped.len()) };
        wrapped.zeroize();
        status
    })
}

/// Unwraps AES-256-KW wrapped key material (RFC 3394).
///
/// # Safety
///
/// `kek` must be valid for `kek_len` bytes (must be 32), and `wrapped` must be
/// valid for `wrapped_len` bytes. `key_data_out` must point to at least
/// `key_data_out_len` writable bytes, and `key_data_len_out` must be a
/// non-null writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes256_kw_unwrap_key(
    kek: *const u8,
    kek_len: usize,
    wrapped: *const u8,
    wrapped_len: usize,
    key_data_out: *mut u8,
    key_data_out_len: usize,
    key_data_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status = validate_output_len_pair(key_data_out, key_data_out_len, key_data_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let kek = match unsafe { read_slice(kek, kek_len) } {
            Ok(value) => match Aes256KwKek::from_slice(value) {
                Ok(kek) => kek,
                Err(error) => return map_unwrap_error(error),
            },
            Err(status) => return status,
        };
        let wrapped = match unsafe { read_slice(wrapped, wrapped_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let expected_len = match wrapped.len().checked_sub(AES_KW_INTEGRITY_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if key_data_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let mut key_data = match unwrap_key(&kek, wrapped) {
            Ok(value) => value.into_vec(),
            Err(error) => return map_unwrap_error(error),
        };
        let status = unsafe { write_fixed(key_data_out, key_data_out_len, &key_data) };
        if status != CRYPTO_OK {
            key_data.zeroize();
            return status;
        }
        let status = unsafe { write_len(key_data_len_out, key_data.len()) };
        key_data.zeroize();
        status
    })
}
