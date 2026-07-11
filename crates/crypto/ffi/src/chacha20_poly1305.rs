// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, validate_output_len_pair, write_fixed, write_len};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_chacha20_poly1305::{
    decrypt, decrypt_xchacha20_poly1305, encrypt, encrypt_xchacha20_poly1305, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    XChaCha20Poly1305DecryptRequest, XChaCha20Poly1305EncryptRequest, XChaCha20Poly1305Nonce,
    CHACHA20_POLY1305_KEY_LENGTH, CHACHA20_POLY1305_NONCE_LENGTH, CHACHA20_POLY1305_TAG_LENGTH,
    XCHACHA20_POLY1305_NONCE_LENGTH,
};
use zeroize::Zeroize;

/// Length in bytes of a ChaCha20-Poly1305 key (32).
pub const CHACHA20_POLY1305_KEY_LEN: usize = CHACHA20_POLY1305_KEY_LENGTH;
/// Length in bytes of an RFC 8439 ChaCha20-Poly1305 nonce (12).
pub const CHACHA20_POLY1305_NONCE_LEN: usize = CHACHA20_POLY1305_NONCE_LENGTH;
/// Length in bytes of an XChaCha20-Poly1305 nonce (24).
pub const XCHACHA20_POLY1305_NONCE_LEN: usize = XCHACHA20_POLY1305_NONCE_LENGTH;
/// Length in bytes of the Poly1305 authentication tag (16).
pub const CHACHA20_POLY1305_TAG_LEN: usize = CHACHA20_POLY1305_TAG_LENGTH;

/// Encrypts `plaintext` with ChaCha20-Poly1305 under `key`/`nonce` and `aad`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_chacha20_poly1305_encrypt(
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
        encrypt_chacha20_poly1305(
            NonceKind::Rfc8439,
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            ciphertext_out,
            ciphertext_out_len,
            ciphertext_len_out,
        )
    })
}

/// Decrypts and authenticates a ChaCha20-Poly1305 `ciphertext || tag`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_chacha20_poly1305_decrypt(
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
        decrypt_chacha20_poly1305(
            NonceKind::Rfc8439,
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            plaintext_out,
            plaintext_out_len,
            plaintext_len_out,
        )
    })
}

/// Encrypts `plaintext` with XChaCha20-Poly1305 under `key`/`nonce` and `aad`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_xchacha20_poly1305_encrypt(
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
        encrypt_chacha20_poly1305(
            NonceKind::XChaCha,
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            ciphertext_out,
            ciphertext_out_len,
            ciphertext_len_out,
        )
    })
}

/// Decrypts and authenticates an XChaCha20-Poly1305 `ciphertext || tag`.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_xchacha20_poly1305_decrypt(
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
        decrypt_chacha20_poly1305(
            NonceKind::XChaCha,
            key,
            key_len,
            nonce,
            nonce_len,
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            plaintext_out,
            plaintext_out_len,
            plaintext_len_out,
        )
    })
}

enum NonceKind {
    Rfc8439,
    XChaCha,
}

#[allow(clippy::too_many_arguments)]
fn encrypt_chacha20_poly1305(
    nonce_kind: NonceKind,
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
    let len_status =
        validate_output_len_pair(ciphertext_out, ciphertext_out_len, ciphertext_len_out);
    if len_status != CRYPTO_OK {
        return len_status;
    }
    let key = match read_key(key, key_len) {
        Ok(value) => value,
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
    let expected_len = match plaintext.len().checked_add(CHACHA20_POLY1305_TAG_LEN) {
        Some(value) => value,
        None => return CRYPTO_INVALID_ARGUMENT,
    };
    if ciphertext_out_len < expected_len {
        return CRYPTO_BUFFER_TOO_SMALL;
    }

    let ciphertext = match nonce_kind {
        NonceKind::Rfc8439 => {
            let nonce = match read_chacha_nonce(nonce, nonce_len) {
                Ok(value) => value,
                Err(status) => return status,
            };
            encrypt(&EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
        }
        NonceKind::XChaCha => {
            let nonce = match read_xchacha_nonce(nonce, nonce_len) {
                Ok(value) => value,
                Err(status) => return status,
            };
            encrypt_xchacha20_poly1305(&XChaCha20Poly1305EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
        }
    };
    let ciphertext = match ciphertext {
        Ok(value) => value,
        Err(_) => return CRYPTO_INTERNAL_ERROR,
    };
    let bytes = ciphertext.as_bytes();
    let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, bytes) };
    if status != CRYPTO_OK {
        return status;
    }
    unsafe { write_len(ciphertext_len_out, bytes.len()) }
}

#[allow(clippy::too_many_arguments)]
fn decrypt_chacha20_poly1305(
    nonce_kind: NonceKind,
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
    let len_status = validate_output_len_pair(plaintext_out, plaintext_out_len, plaintext_len_out);
    if len_status != CRYPTO_OK {
        return len_status;
    }
    let key = match read_key(key, key_len) {
        Ok(value) => value,
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
    if ciphertext_bytes.len() < CHACHA20_POLY1305_TAG_LEN {
        return CRYPTO_INVALID_CIPHERTEXT;
    }
    let expected_len = match ciphertext_bytes
        .len()
        .checked_sub(CHACHA20_POLY1305_TAG_LEN)
    {
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

    let plaintext = match nonce_kind {
        NonceKind::Rfc8439 => {
            let nonce = match read_chacha_nonce(nonce, nonce_len) {
                Ok(value) => value,
                Err(status) => return status,
            };
            decrypt(&DecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
        }
        NonceKind::XChaCha => {
            let nonce = match read_xchacha_nonce(nonce, nonce_len) {
                Ok(value) => value,
                Err(status) => return status,
            };
            decrypt_xchacha20_poly1305(&XChaCha20Poly1305DecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
        }
    };
    let mut plaintext = match plaintext {
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
}

fn read_key(ptr: *const u8, len: usize) -> Result<ChaCha20Poly1305Key, CryptoStatus> {
    match unsafe { read_slice(ptr, len) } {
        Ok(value) => ChaCha20Poly1305Key::from_slice(value).map_err(|_| CRYPTO_INVALID_KEY),
        Err(status) => Err(status),
    }
}

fn read_chacha_nonce(ptr: *const u8, len: usize) -> Result<ChaCha20Poly1305Nonce, CryptoStatus> {
    match unsafe { read_slice(ptr, len) } {
        Ok(value) => ChaCha20Poly1305Nonce::from_slice(value).map_err(|_| CRYPTO_INVALID_ARGUMENT),
        Err(status) => Err(status),
    }
}

fn read_xchacha_nonce(ptr: *const u8, len: usize) -> Result<XChaCha20Poly1305Nonce, CryptoStatus> {
    match unsafe { read_slice(ptr, len) } {
        Ok(value) => XChaCha20Poly1305Nonce::from_slice(value).map_err(|_| CRYPTO_INVALID_ARGUMENT),
        Err(status) => Err(status),
    }
}
