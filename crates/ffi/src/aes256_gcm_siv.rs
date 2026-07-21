// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_output_len_pair, write_fixed, write_len};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_core::AeadAlgorithm;
use reallyme_crypto::aes_gcm_siv::{
    Aes256GcmSivKey, Aes256GcmSivNonce, AES_256_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_NONCE_LENGTH,
    AES_256_GCM_SIV_TAG_LENGTH,
};

/// Length in bytes of an AES-256-GCM-SIV key (32).
pub const AES256_GCM_SIV_KEY_LEN: usize = AES_256_GCM_SIV_KEY_LENGTH;
/// Length in bytes of an AES-256-GCM-SIV nonce (12).
pub const AES256_GCM_SIV_NONCE_LEN: usize = AES_256_GCM_SIV_NONCE_LENGTH;
/// Length in bytes of the AES-256-GCM-SIV authentication tag (16).
pub const AES256_GCM_SIV_TAG_LEN: usize = AES_256_GCM_SIV_TAG_LENGTH;

/// Encrypts `plaintext` with AES-256-GCM-SIV under `key`/`nonce` and `aad`,
/// writing the ciphertext-with-appended-tag to `ciphertext_out` and its length
/// to `ciphertext_len_out`. The output is `plaintext_len + 16` bytes.
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
pub unsafe extern "C" fn rm_crypto_aes256_gcm_siv_encrypt(
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
            Ok(value) => match Aes256GcmSivKey::from_slice(value) {
                Ok(key) => key,
                Err(_) => return CRYPTO_INVALID_KEY,
            },
            Err(status) => return status,
        };
        let nonce = match unsafe { read_slice(nonce, nonce_len) } {
            Ok(value) => match Aes256GcmSivNonce::from_slice(value) {
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

        let expected_len = match plaintext.len().checked_add(AES256_GCM_SIV_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        if ciphertext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let ciphertext = match reallyme_crypto::operations::aead::seal(
            AeadAlgorithm::Aes256GcmSiv,
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

/// Decrypts an AES-256-GCM-SIV ciphertext-with-appended-tag under `key`/`nonce`
/// and `aad`, writing the recovered plaintext to `plaintext_out` and its length
/// to `plaintext_len_out`. The plaintext is `ciphertext_len - 16` bytes.
///
/// # Safety
///
/// `key` (`key_len`, must be 32), `nonce` (`nonce_len`, must be 12), `aad`
/// (`aad_len`), and `ciphertext` (`ciphertext_len`, must be at least 16) must
/// each be valid for their stated lengths (a pointer may be null only when its
/// length is `0`). `plaintext_out` must point to at least `plaintext_out_len`
/// writable bytes, which must be at least `ciphertext_len - 16`.
/// `plaintext_len_out` must be a non-null writable `usize`. Returns
/// [`CryptoStatus`] via the return value: [`CRYPTO_OK`] on success,
/// [`CRYPTO_INVALID_CIPHERTEXT`] for a malformed ciphertext,
/// [`CRYPTO_BUFFER_TOO_SMALL`], or [`CRYPTO_AUTHENTICATION_FAILED`] if tag
/// verification fails.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes256_gcm_siv_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_len: usize,
    plaintext_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let len_status =
            validate_output_len_pair(plaintext_out, plaintext_out_len, plaintext_len_out);
        if len_status != CRYPTO_OK {
            return len_status;
        }
        let key = match unsafe { read_slice(key, key_len) } {
            Ok(value) => match Aes256GcmSivKey::from_slice(value) {
                Ok(key) => key,
                Err(_) => return CRYPTO_INVALID_KEY,
            },
            Err(status) => return status,
        };
        let nonce = match unsafe { read_slice(nonce, nonce_len) } {
            Ok(value) => match Aes256GcmSivNonce::from_slice(value) {
                Ok(nonce) => nonce,
                Err(_) => return CRYPTO_INVALID_ARGUMENT,
            },
            Err(status) => return status,
        };
        let aad = match unsafe { read_slice(aad, aad_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let ciphertext_bytes = match unsafe { read_slice(ciphertext, ciphertext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if ciphertext_bytes.len() < AES256_GCM_SIV_TAG_LEN {
            return CRYPTO_INVALID_CIPHERTEXT;
        }
        let expected_len = match ciphertext_bytes.len().checked_sub(AES256_GCM_SIV_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if plaintext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        let plaintext = match reallyme_crypto::operations::aead::open(
            AeadAlgorithm::Aes256GcmSiv,
            key.as_bytes(),
            nonce.as_bytes(),
            aad,
            ciphertext_bytes,
        ) {
            Ok(value) => value,
            Err(_) => return CRYPTO_AUTHENTICATION_FAILED,
        };
        let status = unsafe { write_fixed(plaintext_out, plaintext_out_len, &plaintext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(plaintext_len_out, plaintext.len()) }
    })
}
