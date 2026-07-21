// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_output_len_pair, write_fixed, write_len};
use crate::status::{
    CryptoStatus, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_ARGUMENT,
    CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_core::AeadAlgorithm;
use reallyme_crypto::aes::{
    Aes128GcmKey, Aes128GcmNonce, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey, Aes256GcmNonce,
};

use super::{AES128_GCM_TAG_LEN, AES192_GCM_TAG_LEN, AES256_GCM_TAG_LEN};

/// Encrypts `plaintext` with AES-128-GCM under `key`/`nonce` and `aad`, writing
/// the ciphertext-with-appended-tag to `ciphertext_out` and its length to
/// `ciphertext_len_out`. The output is `plaintext_len + 16` bytes.
///
/// # Safety
///
/// `key` (`key_len`, must be 16), `nonce` (`nonce_len`, must be 12), `aad`
/// (`aad_len`), and `plaintext` (`plaintext_len`) must each be valid for their
/// stated lengths (a pointer may be null only when its length is `0`).
/// `ciphertext_out` must point to at least `ciphertext_out_len` writable bytes,
/// which must be at least `plaintext_len + 16`. `ciphertext_len_out` must be a
/// non-null writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes128_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    ciphertext_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status =
            validate_output_len_pair(ciphertext_out, ciphertext_out_len, ciphertext_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => match Aes128GcmKey::from_slice(value) {
                Ok(key) => key,
                Err(_) => return CRYPTO_INVALID_KEY,
            },
            Err(status) => return status,
        };
        let nonce = match unsafe { read_slice(nonce, nonce_len) } {
            Ok(value) => match Aes128GcmNonce::from_slice(value) {
                Ok(nonce) => nonce,
                Err(_) => return CRYPTO_INVALID_ARGUMENT,
            },
            Err(status) => return status,
        };
        let aad = match unsafe { read_slice(aad, aad_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let plaintext = match unsafe { read_slice(plaintext, plaintext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        let expected_len = match plaintext.len().checked_add(AES128_GCM_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        if ciphertext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let ciphertext = match reallyme_crypto::operations::aead::seal(
            AeadAlgorithm::Aes128Gcm,
            key.as_bytes(),
            nonce.as_bytes(),
            aad,
            plaintext,
        ) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, &ciphertext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, ciphertext.len()) }
    })
}

/// Encrypts `plaintext` with AES-192-GCM under `key`/`nonce` and `aad`, writing
/// the ciphertext-with-appended-tag to `ciphertext_out` and its length to
/// `ciphertext_len_out`. The output is `plaintext_len + 16` bytes.
///
/// # Safety
///
/// `key` (`key_len`, must be 24), `nonce` (`nonce_len`, must be 12), `aad`
/// (`aad_len`), and `plaintext` (`plaintext_len`) must each be valid for their
/// stated lengths (a pointer may be null only when its length is `0`).
/// `ciphertext_out` must point to at least `ciphertext_out_len` writable bytes,
/// which must be at least `plaintext_len + 16`. `ciphertext_len_out` must be a
/// non-null writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes192_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    ciphertext_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status =
            validate_output_len_pair(ciphertext_out, ciphertext_out_len, ciphertext_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => match Aes192GcmKey::from_slice(value) {
                Ok(key) => key,
                Err(_) => return CRYPTO_INVALID_KEY,
            },
            Err(status) => return status,
        };
        let nonce = match unsafe { read_slice(nonce, nonce_len) } {
            Ok(value) => match Aes192GcmNonce::from_slice(value) {
                Ok(nonce) => nonce,
                Err(_) => return CRYPTO_INVALID_ARGUMENT,
            },
            Err(status) => return status,
        };
        let aad = match unsafe { read_slice(aad, aad_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let plaintext = match unsafe { read_slice(plaintext, plaintext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        let expected_len = match plaintext.len().checked_add(AES192_GCM_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        if ciphertext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let ciphertext = match reallyme_crypto::operations::aead::seal(
            AeadAlgorithm::Aes192Gcm,
            key.as_bytes(),
            nonce.as_bytes(),
            aad,
            plaintext,
        ) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, &ciphertext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, ciphertext.len()) }
    })
}

/// Encrypts `plaintext` with AES-256-GCM under `key`/`nonce` and `aad`, writing
/// the ciphertext-with-appended-tag to `ciphertext_out` and its length to
/// `ciphertext_len_out`. The output is `plaintext_len + 16` bytes.
///
/// # Safety
///
/// `key` (`key_len`, must be 32), `nonce` (`nonce_len`, must be 12), `aad`
/// (`aad_len`), and `plaintext` (`plaintext_len`) must each be valid for their
/// stated lengths (a pointer may be null only when its length is `0`).
/// `ciphertext_out` must point to at least `ciphertext_out_len` writable bytes,
/// which must be at least `plaintext_len + 16`. `ciphertext_len_out` must be a
/// non-null writable `usize`. Returns [`CryptoStatus`] via the return value:
/// [`CRYPTO_OK`] on success, [`CRYPTO_INVALID_KEY`]/[`CRYPTO_INVALID_ARGUMENT`]
/// for bad key/nonce, or [`CRYPTO_BUFFER_TOO_SMALL`].
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes256_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    ciphertext_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status =
            validate_output_len_pair(ciphertext_out, ciphertext_out_len, ciphertext_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => match Aes256GcmKey::from_slice(value) {
                Ok(key) => key,
                Err(_) => return CRYPTO_INVALID_KEY,
            },
            Err(status) => return status,
        };
        let nonce = match unsafe { read_slice(nonce, nonce_len) } {
            Ok(value) => match Aes256GcmNonce::from_slice(value) {
                Ok(nonce) => nonce,
                Err(_) => return CRYPTO_INVALID_ARGUMENT,
            },
            Err(status) => return status,
        };
        let aad = match unsafe { read_slice(aad, aad_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let plaintext = match unsafe { read_slice(plaintext, plaintext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };

        let expected_len = match plaintext.len().checked_add(AES256_GCM_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        if ciphertext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let ciphertext = match reallyme_crypto::operations::aead::seal(
            AeadAlgorithm::Aes256Gcm,
            key.as_bytes(),
            nonce.as_bytes(),
            aad,
            plaintext,
        ) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, &ciphertext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, ciphertext.len()) }
    })
}
