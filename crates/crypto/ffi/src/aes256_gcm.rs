// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_output_len_pair, write_fixed, write_len};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    AES_128_GCM_KEY_LENGTH, AES_128_GCM_NONCE_LENGTH, AES_128_GCM_TAG_LENGTH,
    AES_192_GCM_KEY_LENGTH, AES_192_GCM_NONCE_LENGTH, AES_192_GCM_TAG_LENGTH,
    AES_256_GCM_KEY_LENGTH, AES_256_GCM_NONCE_LENGTH, AES_256_GCM_TAG_LENGTH,
};
use zeroize::Zeroize;

/// Length in bytes of an AES-128-GCM key (16).
pub const AES128_GCM_KEY_LEN: usize = AES_128_GCM_KEY_LENGTH;
/// Length in bytes of an AES-128-GCM nonce (12).
pub const AES128_GCM_NONCE_LEN: usize = AES_128_GCM_NONCE_LENGTH;
/// Length in bytes of the AES-128-GCM authentication tag (16).
pub const AES128_GCM_TAG_LEN: usize = AES_128_GCM_TAG_LENGTH;
/// Length in bytes of an AES-192-GCM key (24).
pub const AES192_GCM_KEY_LEN: usize = AES_192_GCM_KEY_LENGTH;
/// Length in bytes of an AES-192-GCM nonce (12).
pub const AES192_GCM_NONCE_LEN: usize = AES_192_GCM_NONCE_LENGTH;
/// Length in bytes of the AES-192-GCM authentication tag (16).
pub const AES192_GCM_TAG_LEN: usize = AES_192_GCM_TAG_LENGTH;
/// Length in bytes of an AES-256-GCM key (32).
pub const AES256_GCM_KEY_LEN: usize = AES_256_GCM_KEY_LENGTH;
/// Length in bytes of an AES-256-GCM nonce (12).
pub const AES256_GCM_NONCE_LEN: usize = AES_256_GCM_NONCE_LENGTH;
/// Length in bytes of the AES-256-GCM authentication tag (16).
pub const AES256_GCM_TAG_LEN: usize = AES_256_GCM_TAG_LENGTH;

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

        let request = Aes128GcmEncryptRequest {
            key: &key,
            nonce,
            aad,
            plaintext,
        };
        let ciphertext = match encrypt_aes128_gcm(&request) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let bytes = ciphertext.as_bytes();
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, bytes) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, bytes.len()) }
    })
}

/// Decrypts an AES-128-GCM ciphertext-with-appended-tag under `key`/`nonce`
/// and `aad`, writing the recovered plaintext to `plaintext_out` and its length
/// to `plaintext_len_out`. The plaintext is `ciphertext_len - 16` bytes.
///
/// # Safety
///
/// `key` (`key_len`, must be 16), `nonce` (`nonce_len`, must be 12), `aad`
/// (`aad_len`), and `ciphertext` (`ciphertext_len`, must be at least 16) must
/// each be valid for their stated lengths (a pointer may be null only when its
/// length is `0`). `plaintext_out` must point to at least `plaintext_out_len`
/// writable bytes, which must be at least `ciphertext_len - 16`.
/// `plaintext_len_out` must be a non-null writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes128_gcm_decrypt(
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
        let ciphertext_bytes = match unsafe { read_slice(ciphertext, ciphertext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if ciphertext_bytes.len() < AES128_GCM_TAG_LEN {
            return CRYPTO_INVALID_CIPHERTEXT;
        }
        let expected_len = match ciphertext_bytes.len().checked_sub(AES128_GCM_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if plaintext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        let ciphertext = match CiphertextWithTag::from_vec(ciphertext_bytes.to_vec()) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_CIPHERTEXT,
        };

        let request = Aes128GcmDecryptRequest {
            key: &key,
            nonce,
            aad,
            ciphertext: &ciphertext,
        };
        let mut plaintext = match decrypt_aes128_gcm(&request) {
            Ok(value) => value,
            Err(_) => return CRYPTO_AUTHENTICATION_FAILED,
        };
        let status = unsafe { write_fixed(plaintext_out, plaintext_out_len, &plaintext) };
        if status != CRYPTO_OK {
            plaintext.zeroize();
            return status;
        }
        let status = unsafe { write_len(plaintext_len_out, plaintext.len()) };
        plaintext.zeroize();
        status
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

        let request = Aes192GcmEncryptRequest {
            key: &key,
            nonce,
            aad,
            plaintext,
        };
        let ciphertext = match encrypt_aes192_gcm(&request) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let bytes = ciphertext.as_bytes();
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, bytes) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, bytes.len()) }
    })
}

/// Decrypts an AES-192-GCM ciphertext-with-appended-tag under `key`/`nonce`
/// and `aad`, writing the recovered plaintext to `plaintext_out` and its length
/// to `plaintext_len_out`. The plaintext is `ciphertext_len - 16` bytes.
///
/// # Safety
///
/// `key` (`key_len`, must be 24), `nonce` (`nonce_len`, must be 12), `aad`
/// (`aad_len`), and `ciphertext` (`ciphertext_len`, must be at least 16) must
/// each be valid for their stated lengths (a pointer may be null only when its
/// length is `0`). `plaintext_out` must point to at least `plaintext_out_len`
/// writable bytes, which must be at least `ciphertext_len - 16`.
/// `plaintext_len_out` must be a non-null writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_aes192_gcm_decrypt(
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
        let ciphertext_bytes = match unsafe { read_slice(ciphertext, ciphertext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if ciphertext_bytes.len() < AES192_GCM_TAG_LEN {
            return CRYPTO_INVALID_CIPHERTEXT;
        }
        let expected_len = match ciphertext_bytes.len().checked_sub(AES192_GCM_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if plaintext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        let ciphertext = match CiphertextWithTag::from_vec(ciphertext_bytes.to_vec()) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_CIPHERTEXT,
        };

        let request = Aes192GcmDecryptRequest {
            key: &key,
            nonce,
            aad,
            ciphertext: &ciphertext,
        };
        let mut plaintext = match decrypt_aes192_gcm(&request) {
            Ok(value) => value,
            Err(_) => return CRYPTO_AUTHENTICATION_FAILED,
        };
        let status = unsafe { write_fixed(plaintext_out, plaintext_out_len, &plaintext) };
        if status != CRYPTO_OK {
            plaintext.zeroize();
            return status;
        }
        let status = unsafe { write_len(plaintext_len_out, plaintext.len()) };
        plaintext.zeroize();
        status
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

        let request = EncryptRequest {
            key: &key,
            nonce,
            aad,
            plaintext,
        };
        let ciphertext = match encrypt(&request) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        let bytes = ciphertext.as_bytes();
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, bytes) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, bytes.len()) }
    })
}

/// Decrypts an AES-256-GCM ciphertext-with-appended-tag under `key`/`nonce`
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
pub unsafe extern "C" fn rm_crypto_aes256_gcm_decrypt(
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
        let ciphertext_bytes = match unsafe { read_slice(ciphertext, ciphertext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        if ciphertext_bytes.len() < AES256_GCM_TAG_LEN {
            return CRYPTO_INVALID_CIPHERTEXT;
        }
        let expected_len = match ciphertext_bytes.len().checked_sub(AES256_GCM_TAG_LEN) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if plaintext_out_len < expected_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }
        let ciphertext = match CiphertextWithTag::from_vec(ciphertext_bytes.to_vec()) {
            Ok(value) => value,
            Err(_) => return CRYPTO_INVALID_CIPHERTEXT,
        };

        let request = DecryptRequest {
            key: &key,
            nonce,
            aad,
            ciphertext: &ciphertext,
        };
        let mut plaintext = match decrypt(&request) {
            Ok(value) => value,
            Err(_) => return CRYPTO_AUTHENTICATION_FAILED,
        };
        let status = unsafe { write_fixed(plaintext_out, plaintext_out_len, &plaintext) };
        if status != CRYPTO_OK {
            plaintext.zeroize();
            return status;
        }
        let status = unsafe { write_len(plaintext_len_out, plaintext.len()) };
        plaintext.zeroize();
        status
    })
}
