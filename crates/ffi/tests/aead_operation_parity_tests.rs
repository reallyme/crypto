// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(unsafe_code)]

//! C ABI parity tests for AEAD routes backed by the operation owner.

use crypto_core::AeadAlgorithm;
use crypto_ffi::{aes256_gcm, aes256_gcm_siv, chacha20_poly1305, status};

type EncryptFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> status::CryptoStatus;

type DecryptFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> status::CryptoStatus;

struct AeadFfiCase {
    algorithm: AeadAlgorithm,
    key_len: usize,
    nonce_len: usize,
    encrypt: EncryptFn,
    decrypt: DecryptFn,
}

const AEAD_FFI_CASES: &[AeadFfiCase] = &[
    AeadFfiCase {
        algorithm: AeadAlgorithm::Aes128Gcm,
        key_len: aes256_gcm::AES128_GCM_KEY_LEN,
        nonce_len: aes256_gcm::AES128_GCM_NONCE_LEN,
        encrypt: aes256_gcm::rm_crypto_aes128_gcm_encrypt,
        decrypt: aes256_gcm::rm_crypto_aes128_gcm_decrypt,
    },
    AeadFfiCase {
        algorithm: AeadAlgorithm::Aes192Gcm,
        key_len: aes256_gcm::AES192_GCM_KEY_LEN,
        nonce_len: aes256_gcm::AES192_GCM_NONCE_LEN,
        encrypt: aes256_gcm::rm_crypto_aes192_gcm_encrypt,
        decrypt: aes256_gcm::rm_crypto_aes192_gcm_decrypt,
    },
    AeadFfiCase {
        algorithm: AeadAlgorithm::Aes256Gcm,
        key_len: aes256_gcm::AES256_GCM_KEY_LEN,
        nonce_len: aes256_gcm::AES256_GCM_NONCE_LEN,
        encrypt: aes256_gcm::rm_crypto_aes256_gcm_encrypt,
        decrypt: aes256_gcm::rm_crypto_aes256_gcm_decrypt,
    },
    AeadFfiCase {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_len: aes256_gcm_siv::AES256_GCM_SIV_KEY_LEN,
        nonce_len: aes256_gcm_siv::AES256_GCM_SIV_NONCE_LEN,
        encrypt: aes256_gcm_siv::rm_crypto_aes256_gcm_siv_encrypt,
        decrypt: aes256_gcm_siv::rm_crypto_aes256_gcm_siv_decrypt,
    },
    AeadFfiCase {
        algorithm: AeadAlgorithm::ChaCha20Poly1305,
        key_len: chacha20_poly1305::CHACHA20_POLY1305_KEY_LEN,
        nonce_len: chacha20_poly1305::CHACHA20_POLY1305_NONCE_LEN,
        encrypt: chacha20_poly1305::rm_crypto_chacha20_poly1305_encrypt,
        decrypt: chacha20_poly1305::rm_crypto_chacha20_poly1305_decrypt,
    },
    AeadFfiCase {
        algorithm: AeadAlgorithm::XChaCha20Poly1305,
        key_len: chacha20_poly1305::CHACHA20_POLY1305_KEY_LEN,
        nonce_len: chacha20_poly1305::XCHACHA20_POLY1305_NONCE_LEN,
        encrypt: chacha20_poly1305::rm_crypto_xchacha20_poly1305_encrypt,
        decrypt: chacha20_poly1305::rm_crypto_xchacha20_poly1305_decrypt,
    },
];

#[test]
fn c_abi_aead_routes_match_operation_owner_and_reject_tampering() {
    let aad = b"AEAD ffi aad";
    let plaintext = b"AEAD ffi plaintext";

    for case in AEAD_FFI_CASES {
        let key = bytes(case.key_len, 0x21);
        let nonce = bytes(case.nonce_len, 0x63);
        let expected_ciphertext =
            reallyme_crypto::operations::aead::seal(case.algorithm, &key, &nonce, aad, plaintext)
                .expect("AEAD operation seal succeeds");

        let mut ciphertext = vec![0u8; expected_ciphertext.len()];
        let mut ciphertext_len = 0usize;
        let status = unsafe {
            (case.encrypt)(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                &mut ciphertext_len,
            )
        };
        assert_eq!(status, status::CRYPTO_OK);
        assert_eq!(ciphertext_len, expected_ciphertext.len());
        assert_eq!(ciphertext, expected_ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        let mut decrypted_len = 0usize;
        let status = unsafe {
            (case.decrypt)(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext_len,
                decrypted.as_mut_ptr(),
                decrypted.len(),
                &mut decrypted_len,
            )
        };
        assert_eq!(status, status::CRYPTO_OK);
        assert_eq!(decrypted_len, plaintext.len());
        assert_eq!(decrypted, plaintext);

        let first = ciphertext
            .first_mut()
            .expect("ciphertext with tag is not empty");
        *first ^= 0x01;
        let status = unsafe {
            (case.decrypt)(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext_len,
                decrypted.as_mut_ptr(),
                decrypted.len(),
                &mut decrypted_len,
            )
        };
        assert_eq!(status, status::CRYPTO_AUTHENTICATION_FAILED);
    }
}

#[test]
fn c_abi_aead_seal_rejects_oversized_plaintext_without_mutating_output() {
    let aad = b"AEAD oversized ffi aad";
    let oversized_plaintext = core::ptr::NonNull::<u8>::dangling().as_ptr();

    for case in AEAD_FFI_CASES {
        let key = bytes(case.key_len, 0x21);
        let nonce = bytes(case.nonce_len, 0x63);
        let mut ciphertext = [0xa5_u8; 64];
        let mut ciphertext_len = 0_usize;

        let status = unsafe {
            (case.encrypt)(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                oversized_plaintext,
                usize::MAX,
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                &mut ciphertext_len,
            )
        };

        assert_eq!(status, status::CRYPTO_INVALID_ARGUMENT);
        assert_eq!(ciphertext, [0xa5_u8; 64]);
        assert_eq!(ciphertext_len, 0);
    }
}

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index).expect("test vector length fits in u8")))
        .collect()
}
