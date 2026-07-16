// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::panic)]
#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_chacha20_poly1305::{
    decrypt, decrypt_xchacha20_poly1305, encrypt, encrypt_xchacha20_poly1305, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    XChaCha20Poly1305DecryptRequest, XChaCha20Poly1305EncryptRequest, XChaCha20Poly1305Nonce,
    CHACHA20_POLY1305_TAG_LENGTH,
};
use crypto_core::CryptoError;

fn test_key() -> ChaCha20Poly1305Key {
    ChaCha20Poly1305Key::from_slice(&[0x11u8; 32]).expect("test key must be valid")
}

fn test_nonce() -> ChaCha20Poly1305Nonce {
    ChaCha20Poly1305Nonce::from_slice(&[0x22u8; 12]).expect("test nonce must be valid")
}

fn test_xnonce() -> XChaCha20Poly1305Nonce {
    XChaCha20Poly1305Nonce::from_slice(&[0x33u8; 24]).expect("test nonce must be valid")
}

#[test]
fn chacha20_poly1305_encrypt_then_decrypt_roundtrip() {
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
fn xchacha20_poly1305_encrypt_then_decrypt_roundtrip() {
    let key = test_key();
    let nonce = test_xnonce();
    let aad = b"associated-data";
    let plaintext = b"top secret payload";

    let encrypted = encrypt_xchacha20_poly1305(&XChaCha20Poly1305EncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    })
    .expect("encryption should succeed");

    let decrypted = decrypt_xchacha20_poly1305(&XChaCha20Poly1305DecryptRequest {
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

    assert_eq!(encrypted.as_bytes().len(), CHACHA20_POLY1305_TAG_LENGTH);
}

#[test]
fn invalid_key_length_is_rejected() {
    for actual in [0usize, 1, 31, 33, 64] {
        let input = vec![0u8; actual];
        let err = match ChaCha20Poly1305Key::from_slice(&input) {
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
fn invalid_nonce_lengths_are_rejected() {
    for actual in [0usize, 1, 11, 13, 24] {
        let input = vec![0u8; actual];
        let err = ChaCha20Poly1305Nonce::from_slice(&input).expect_err("invalid nonce must fail");

        match err {
            CryptoError::InvalidAeadNonceLength { expected, actual } => {
                assert_eq!(expected, 12);
                assert_eq!(actual, input.len());
            }
            _ => panic!("unexpected error variant for invalid nonce length"),
        }
    }

    for actual in [0usize, 1, 12, 23, 25] {
        let input = vec![0u8; actual];
        let err = XChaCha20Poly1305Nonce::from_slice(&input).expect_err("invalid nonce must fail");

        match err {
            CryptoError::InvalidAeadNonceLength { expected, actual } => {
                assert_eq!(expected, 24);
                assert_eq!(actual, input.len());
            }
            _ => panic!("unexpected error variant for invalid nonce length"),
        }
    }
}

#[test]
fn too_short_ciphertext_is_rejected() {
    for expected_actual in 0usize..CHACHA20_POLY1305_TAG_LENGTH {
        let err = CiphertextWithTag::from_vec(vec![0u8; expected_actual])
            .expect_err("ciphertext shorter than tag must fail");

        match err {
            CryptoError::InvalidCiphertextLength { minimum, actual } => {
                assert_eq!(minimum, CHACHA20_POLY1305_TAG_LENGTH);
                assert_eq!(actual, expected_actual);
            }
            _ => panic!("unexpected error variant for invalid ciphertext length"),
        }
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
    let tampered = CiphertextWithTag::from_vec(tampered).expect("tampered bytes keep shape");

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
