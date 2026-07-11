// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(feature = "native")]

use crypto_aes256_gcm::{
    decrypt, encrypt, Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
    EncryptRequest, AES_256_GCM_TAG_LENGTH,
};
use crypto_core::CryptoError;

mod vectors;

fn test_key() -> Aes256GcmKey {
    let key_bytes = [0x11u8; 32];
    Aes256GcmKey::from_slice(&key_bytes).expect("test key must be valid")
}

fn test_nonce() -> Aes256GcmNonce {
    let nonce_bytes = [0x22u8; 12];
    Aes256GcmNonce::from_slice(&nonce_bytes).expect("test nonce must be valid")
}

#[test]
fn encrypt_then_decrypt_roundtrip() {
    let key = test_key();
    let nonce = test_nonce();
    let aad = b"associated-data";
    let plaintext = b"top secret payload";

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    })
    .expect("encryption should succeed");

    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &encrypted,
    })
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn empty_plaintext_is_supported() {
    let key = test_key();
    let nonce = test_nonce();

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"",
        plaintext: b"",
    })
    .expect("encryption should succeed");

    assert_eq!(encrypted.as_bytes().len(), AES_256_GCM_TAG_LENGTH);

    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"",
        ciphertext: &encrypted,
    })
    .expect("decryption should succeed");

    assert!(decrypted.is_empty());
}

#[test]
fn invalid_key_length_is_rejected() {
    for actual in [0usize, 1, 31, 33, 64] {
        let input = vec![0u8; actual];
        let err = match Aes256GcmKey::from_slice(&input) {
            Err(err) => err,
            Ok(_) => panic!("invalid key length {actual} must fail"),
        };

        match err {
            CryptoError::InvalidAeadKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, input.len());
            }
            _ => panic!("unexpected error variant for invalid key length"),
        }
    }
}

#[test]
fn invalid_nonce_length_is_rejected() {
    for actual in [0usize, 1, 11, 13, 24] {
        let input = vec![0u8; actual];
        let err = Aes256GcmNonce::from_slice(&input).expect_err("invalid nonce length must fail");

        match err {
            CryptoError::InvalidAeadNonceLength { expected, actual } => {
                assert_eq!(expected, 12);
                assert_eq!(actual, input.len());
            }
            _ => panic!("unexpected error variant for invalid nonce length"),
        }
    }
}

#[test]
fn too_short_ciphertext_is_rejected() {
    for expected_actual in 0usize..AES_256_GCM_TAG_LENGTH {
        let err = CiphertextWithTag::from_vec(vec![0u8; expected_actual])
            .expect_err("ciphertext shorter than tag must fail");

        match err {
            CryptoError::InvalidCiphertextLength { minimum, actual } => {
                assert_eq!(minimum, AES_256_GCM_TAG_LENGTH);
                assert_eq!(actual, expected_actual);
            }
            _ => panic!("unexpected error variant for invalid ciphertext length"),
        }
    }
}

#[test]
fn decryption_fails_with_wrong_key() {
    let key = test_key();
    let nonce = test_nonce();

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        plaintext: b"plaintext",
    })
    .expect("encryption should succeed");

    let wrong_key = Aes256GcmKey::from_slice(&[0x33u8; 32]).expect("test key must be valid");

    let err = decrypt(&DecryptRequest {
        key: &wrong_key,
        nonce,
        aad: b"aad",
        ciphertext: &encrypted,
    })
    .expect_err("decryption with wrong key must fail");

    match err {
        CryptoError::AeadDecrypt { .. } => {}
        _ => panic!("unexpected error variant for wrong key"),
    }
}

#[test]
fn decryption_fails_with_tampered_ciphertext() {
    let key = test_key();
    let nonce = test_nonce();

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        plaintext: b"plaintext",
    })
    .expect("encryption should succeed");

    let mut tampered = encrypted.into_vec();
    tampered[0] ^= 0x80;

    let tampered = CiphertextWithTag::from_vec(tampered).expect("tampered bytes keep valid shape");

    let err = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        ciphertext: &tampered,
    })
    .expect_err("tampered ciphertext must fail authentication");

    match err {
        CryptoError::AeadDecrypt { .. } => {}
        _ => panic!("unexpected error variant for tampered ciphertext"),
    }
}

#[test]
fn decryption_fails_when_aad_does_not_match() {
    let key = test_key();
    let nonce = test_nonce();

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"aad-one",
        plaintext: b"plaintext",
    })
    .expect("encryption should succeed");

    let err = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"aad-two",
        ciphertext: &encrypted,
    })
    .expect_err("AAD mismatch must fail authentication");

    match err {
        CryptoError::AeadDecrypt { .. } => {}
        _ => panic!("unexpected error variant for AAD mismatch"),
    }
}

#[test]
fn nist_vector_encrypt_and_decrypt_matches() {
    for vector in vectors::all_regression_vectors() {
        let key = Aes256GcmKey::from_slice(&vector.key).expect("vector key must be valid");
        let nonce = Aes256GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");

        let encrypted = encrypt(&EncryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            plaintext: &vector.plaintext,
        })
        .expect("vector encryption should succeed");

        assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

        let decrypted = decrypt(&DecryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            ciphertext: &encrypted,
        })
        .expect("vector decryption should succeed");

        assert_eq!(decrypted, vector.plaintext);
    }
}
