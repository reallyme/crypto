// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{
    read_slice, validate_disjoint_len_outputs, validate_disjoint_output_pair,
    validate_output_len_pair, write_fixed, write_len,
};
use crate::status::{
    CryptoStatus, CRYPTO_AUTHENTICATION_FAILED, CRYPTO_BUFFER_TOO_SMALL, CRYPTO_INTERNAL_ERROR,
    CRYPTO_INVALID_ARGUMENT, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY, CRYPTO_OK,
};
use crypto_hpke::{
    open_base, seal_base, HpkeError, HpkeOpenRequest, HpkeSealRequest, HpkeSuite,
    HPKE_AEAD_TAG_LEN, HPKE_ENCAPSULATED_KEY_MAX_LEN, HPKE_P256_PRIVATE_KEY_LEN,
    HPKE_P256_PUBLIC_KEY_LEN, HPKE_X25519_PRIVATE_KEY_LEN, HPKE_X25519_PUBLIC_KEY_LEN,
};
use zeroize::Zeroize;

/// FFI suite selector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
pub const HPKE_SUITE_P256_SHA256_AES256GCM: u32 = 1;
/// FFI suite selector for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
pub const HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305: u32 = 2;

/// Maximum encapsulated key length for supported HPKE suites.
pub const HPKE_FFI_ENCAPSULATED_KEY_MAX_LEN: usize = HPKE_ENCAPSULATED_KEY_MAX_LEN;
/// HPKE P-256 recipient public key length.
pub const HPKE_FFI_P256_PUBLIC_KEY_LEN: usize = HPKE_P256_PUBLIC_KEY_LEN;
/// HPKE P-256 recipient private key length.
pub const HPKE_FFI_P256_PRIVATE_KEY_LEN: usize = HPKE_P256_PRIVATE_KEY_LEN;
/// HPKE X25519 recipient public key length.
pub const HPKE_FFI_X25519_PUBLIC_KEY_LEN: usize = HPKE_X25519_PUBLIC_KEY_LEN;
/// HPKE X25519 recipient private key length.
pub const HPKE_FFI_X25519_PRIVATE_KEY_LEN: usize = HPKE_X25519_PRIVATE_KEY_LEN;
/// HPKE AEAD tag length for supported suites.
pub const HPKE_FFI_AEAD_TAG_LEN: usize = HPKE_AEAD_TAG_LEN;

/// Encrypts one message with HPKE Base mode.
///
/// # Safety
///
/// All pointer/length pairs must be valid for their stated lengths, with null
/// pointers permitted only when the corresponding length is `0`.
/// `encapsulated_key_out` must hold the suite-specific encapsulated key length,
/// and `ciphertext_out` must hold `plaintext_len + 16` bytes. The produced
/// lengths are written through non-null `*_len_out` pointers.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_hpke_seal_base(
    suite: u32,
    recipient_public_key: *const u8,
    recipient_public_key_len: usize,
    info: *const u8,
    info_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    encapsulated_key_out: *mut u8,
    encapsulated_key_out_len: usize,
    encapsulated_key_len_out: *mut usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    ciphertext_len_out: *mut usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let encapsulated_len_status = validate_output_len_pair(
            encapsulated_key_out,
            encapsulated_key_out_len,
            encapsulated_key_len_out,
        );
        if encapsulated_len_status != CRYPTO_OK {
            return encapsulated_len_status;
        }
        let ciphertext_len_status =
            validate_output_len_pair(ciphertext_out, ciphertext_out_len, ciphertext_len_out);
        if ciphertext_len_status != CRYPTO_OK {
            return ciphertext_len_status;
        }
        let output_status = validate_disjoint_output_pair(
            encapsulated_key_out,
            encapsulated_key_out_len,
            ciphertext_out,
            ciphertext_out_len,
        );
        if output_status != CRYPTO_OK {
            return output_status;
        }
        let len_output_status =
            validate_disjoint_len_outputs(encapsulated_key_len_out, ciphertext_len_out);
        if len_output_status != CRYPTO_OK {
            return len_output_status;
        }
        let suite = match hpke_suite(suite) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let recipient_public_key =
            match unsafe { read_slice(recipient_public_key, recipient_public_key_len) } {
                Ok(value) => value,
                Err(status) => return status,
            };
        let info = match unsafe { read_slice(info, info_len) } {
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

        let expected_ciphertext_len = match plaintext.len().checked_add(suite.tag_len()) {
            Some(value) => value,
            None => return CRYPTO_INVALID_ARGUMENT,
        };
        if encapsulated_key_out_len < suite.public_key_len()
            || ciphertext_out_len < expected_ciphertext_len
        {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let sealed = match seal_base(&HpkeSealRequest {
            suite,
            recipient_public_key,
            info,
            aad,
            plaintext,
        }) {
            Ok(value) => value,
            Err(error) => return seal_status(error),
        };

        let status = unsafe {
            write_fixed(
                encapsulated_key_out,
                encapsulated_key_out_len,
                &sealed.encapsulated_key,
            )
        };
        if status != CRYPTO_OK {
            return status;
        }
        let status = unsafe { write_len(encapsulated_key_len_out, sealed.encapsulated_key.len()) };
        if status != CRYPTO_OK {
            return status;
        }
        let status = unsafe { write_fixed(ciphertext_out, ciphertext_out_len, &sealed.ciphertext) };
        if status != CRYPTO_OK {
            return status;
        }
        unsafe { write_len(ciphertext_len_out, sealed.ciphertext.len()) }
    })
}

/// Decrypts one message with HPKE Base mode.
///
/// # Safety
///
/// All pointer/length pairs must be valid for their stated lengths, with null
/// pointers permitted only when the corresponding length is `0`. `plaintext_out`
/// must hold at least `ciphertext_len - 16` bytes for non-empty ciphertexts, and
/// `plaintext_len_out` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_hpke_open_base(
    suite: u32,
    encapsulated_key: *const u8,
    encapsulated_key_len: usize,
    recipient_private_key: *const u8,
    recipient_private_key_len: usize,
    info: *const u8,
    info_len: usize,
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
        let suite = match hpke_suite(suite) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let encapsulated_key = match unsafe { read_slice(encapsulated_key, encapsulated_key_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let recipient_private_key =
            match unsafe { read_slice(recipient_private_key, recipient_private_key_len) } {
                Ok(value) => value,
                Err(status) => return status,
            };
        let info = match unsafe { read_slice(info, info_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let aad = match unsafe { read_slice(aad, aad_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let ciphertext = match unsafe { read_slice(ciphertext, ciphertext_len) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        let expected_plaintext_len = match ciphertext.len().checked_sub(suite.tag_len()) {
            Some(value) => value,
            None => return CRYPTO_INVALID_CIPHERTEXT,
        };
        if plaintext_out_len < expected_plaintext_len {
            return CRYPTO_BUFFER_TOO_SMALL;
        }

        let mut opened = match open_base(&HpkeOpenRequest {
            suite,
            encapsulated_key,
            recipient_private_key,
            info,
            aad,
            ciphertext,
        }) {
            Ok(value) => value,
            Err(error) => return open_status(error),
        };

        let status = unsafe { write_fixed(plaintext_out, plaintext_out_len, &opened.plaintext) };
        if status != CRYPTO_OK {
            opened.plaintext.zeroize();
            return status;
        }
        let status = unsafe { write_len(plaintext_len_out, opened.plaintext.len()) };
        opened.plaintext.zeroize();
        status
    })
}

fn hpke_suite(suite: u32) -> Result<HpkeSuite, CryptoStatus> {
    match suite {
        HPKE_SUITE_P256_SHA256_AES256GCM => Ok(HpkeSuite::P256Sha256Aes256Gcm),
        HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305 => Ok(HpkeSuite::X25519Sha256ChaCha20Poly1305),
        _ => Err(CRYPTO_INVALID_ARGUMENT),
    }
}

fn seal_status(error: HpkeError) -> CryptoStatus {
    match error {
        HpkeError::InvalidPublicKey => CRYPTO_INVALID_KEY,
        HpkeError::InvalidCiphertext | HpkeError::InvalidEncapsulatedKey => {
            CRYPTO_INVALID_CIPHERTEXT
        }
        HpkeError::UnsupportedSuite | HpkeError::LengthOverflow => CRYPTO_INVALID_ARGUMENT,
        HpkeError::InvalidRandomness => CRYPTO_INVALID_ARGUMENT,
        HpkeError::InvalidPrivateKey | HpkeError::SealFailed | HpkeError::OpenFailed => {
            CRYPTO_INTERNAL_ERROR
        }
    }
}

fn open_status(error: HpkeError) -> CryptoStatus {
    match error {
        HpkeError::InvalidPrivateKey => CRYPTO_INVALID_KEY,
        HpkeError::InvalidCiphertext | HpkeError::InvalidEncapsulatedKey => {
            CRYPTO_INVALID_CIPHERTEXT
        }
        HpkeError::InvalidPublicKey | HpkeError::UnsupportedSuite | HpkeError::LengthOverflow => {
            CRYPTO_INVALID_ARGUMENT
        }
        HpkeError::InvalidRandomness => CRYPTO_INVALID_ARGUMENT,
        HpkeError::OpenFailed => CRYPTO_AUTHENTICATION_FAILED,
        HpkeError::SealFailed => CRYPTO_INTERNAL_ERROR,
    }
}
