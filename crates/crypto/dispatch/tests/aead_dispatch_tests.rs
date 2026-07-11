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

use crypto_core::{AeadAlgorithm, CryptoError};
use crypto_dispatch::{aead_decrypt, aead_encrypt, AeadParams, AlgorithmError};

struct DispatchAesVector {
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext_and_tag: Vec<u8>,
}

fn regression_vectors() -> Vec<DispatchAesVector> {
    vec![
        DispatchAesVector {
            key: hex::decode(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            )
            .expect("vector key must decode"),
            nonce: hex::decode("cafebabefacedbaddecaf888").expect("vector nonce must decode"),
            aad: hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
                .expect("vector aad must decode"),
            plaintext: hex::decode(
                "d9313225f88406e5a55909c5aff5269a\
                 86a7a9531534f7da2e4c303d8a318a72\
                 1c3c0c95956809532fcf0e2449a6b525\
                 b16aedf5aa0de657ba637b39",
            )
            .expect("vector plaintext must decode"),
            ciphertext_and_tag: hex::decode(
                "522dc1f099567d07f47f37a32a84427d\
                 643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838\
                 c5f61e6393ba7a0abcc9f662\
                 76fc6ece0f4e1768cddf8853bb2d551b",
            )
            .expect("vector ciphertext must decode"),
        },
        DispatchAesVector {
            key: hex::decode(
                "000102030405060708090a0b0c0d0e0f\
                 101112131415161718191a1b1c1d1e1f",
            )
            .expect("vector key must decode"),
            nonce: hex::decode("1af38c2dc2b96ffdd8669409").expect("vector nonce must decode"),
            aad: hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
                .expect("vector aad must decode"),
            plaintext: hex::decode(
                "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
            )
            .expect("vector plaintext must decode"),
            ciphertext_and_tag: hex::decode(
                "e350fda4478983335c52877b20d06795e873a81098f41a02d6e91a3067a30e902b50168b74a6c94192b95dc5d3ee30c1e6aaa04ba81bd2d1ea5303b08760b1bfb92a354cf9d7f749c7d251cd0bee0be651873f329ddd216493a6cd469776655d4b8d89f43520d4fabeba28235c0cc8ffd2e98c56cfb8a834aa453df707baaf88f586dd6898d35f51b5c39744a0e95191",
            )
            .expect("vector ciphertext must decode"),
        },
    ]
}

#[test]
fn aes256_gcm_dispatch_roundtrip() {
    let key = [0xAA; 32];
    let nonce = [0xBB; 12];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-aad",
    };

    let encrypted = aead_encrypt(AeadAlgorithm::Aes256Gcm, &params, b"dispatch-plaintext")
        .expect("dispatch encryption should succeed");

    let decrypted = aead_decrypt(AeadAlgorithm::Aes256Gcm, &params, &encrypted)
        .expect("dispatch decryption should succeed");

    assert_eq!(decrypted.as_slice(), b"dispatch-plaintext");
}

#[test]
fn aes256_gcm_dispatch_rejects_modified_ciphertext() {
    let key = [0xAA; 32];
    let nonce = [0xBB; 12];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-aad",
    };

    let encrypted = aead_encrypt(AeadAlgorithm::Aes256Gcm, &params, b"dispatch-plaintext")
        .expect("dispatch encryption should succeed");

    let mut bytes = encrypted;
    bytes[0] ^= 0x01;

    let err = aead_decrypt(AeadAlgorithm::Aes256Gcm, &params, &bytes)
        .expect_err("tampered ciphertext must fail authentication");

    match err {
        AlgorithmError::Crypto(CryptoError::AeadDecrypt { .. }) => {}
        _ => panic!("unexpected error variant for tampered ciphertext"),
    }
}

#[test]
fn aes256_gcm_dispatch_matches_regression_vectors() {
    for vector in regression_vectors() {
        let params = AeadParams {
            key: &vector.key,
            nonce: &vector.nonce,
            aad: &vector.aad,
        };

        let encrypted = aead_encrypt(AeadAlgorithm::Aes256Gcm, &params, &vector.plaintext)
            .expect("dispatch encryption must succeed");

        assert_eq!(encrypted, vector.ciphertext_and_tag);

        let decrypted = aead_decrypt(AeadAlgorithm::Aes256Gcm, &params, &encrypted)
            .expect("dispatch decryption must succeed");

        assert_eq!(decrypted.as_slice(), vector.plaintext);
    }
}

#[test]
fn aes256_gcm_siv_dispatch_roundtrip() {
    let key = [0x11; 32];
    let nonce = [0x22; 12];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-siv-aad",
    };

    let encrypted = aead_encrypt(
        AeadAlgorithm::Aes256GcmSiv,
        &params,
        b"dispatch-siv-plaintext",
    )
    .expect("AES-GCM-SIV dispatch encryption should succeed");

    let decrypted = aead_decrypt(AeadAlgorithm::Aes256GcmSiv, &params, &encrypted)
        .expect("AES-GCM-SIV dispatch decryption should succeed");

    assert_eq!(decrypted.as_slice(), b"dispatch-siv-plaintext");
}

#[test]
fn chacha20_poly1305_dispatch_roundtrip() {
    let key = [0x44; 32];
    let nonce = [0x55; 12];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-chacha-aad",
    };

    let encrypted = aead_encrypt(
        AeadAlgorithm::ChaCha20Poly1305,
        &params,
        b"dispatch-chacha-plaintext",
    )
    .expect("ChaCha20-Poly1305 dispatch encryption should succeed");

    let decrypted = aead_decrypt(AeadAlgorithm::ChaCha20Poly1305, &params, &encrypted)
        .expect("ChaCha20-Poly1305 dispatch decryption should succeed");

    assert_eq!(decrypted.as_slice(), b"dispatch-chacha-plaintext");
}

#[test]
fn xchacha20_poly1305_dispatch_roundtrip() {
    let key = [0x66; 32];
    let nonce = [0x77; 24];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-xchacha-aad",
    };

    let encrypted = aead_encrypt(
        AeadAlgorithm::XChaCha20Poly1305,
        &params,
        b"dispatch-xchacha-plaintext",
    )
    .expect("XChaCha20-Poly1305 dispatch encryption should succeed");

    let decrypted = aead_decrypt(AeadAlgorithm::XChaCha20Poly1305, &params, &encrypted)
        .expect("XChaCha20-Poly1305 dispatch decryption should succeed");

    assert_eq!(decrypted.as_slice(), b"dispatch-xchacha-plaintext");
}

#[test]
fn chacha20_poly1305_dispatch_rejects_xchacha_nonce_length() {
    let key = [0x44; 32];
    let nonce = [0x55; 24];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-chacha-aad",
    };

    let err = aead_encrypt(
        AeadAlgorithm::ChaCha20Poly1305,
        &params,
        b"dispatch-chacha-plaintext",
    )
    .expect_err("ChaCha20-Poly1305 must reject a 24-byte nonce");

    match err {
        AlgorithmError::Crypto(CryptoError::InvalidAeadNonceLength { expected, actual }) => {
            assert_eq!(expected, 12);
            assert_eq!(actual, nonce.len());
        }
        _ => panic!("unexpected error variant for invalid nonce length"),
    }
}

#[test]
fn xchacha20_poly1305_dispatch_rejects_chacha_nonce_length() {
    let key = [0x66; 32];
    let nonce = [0x77; 12];
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad: b"dispatch-xchacha-aad",
    };

    let err = aead_encrypt(
        AeadAlgorithm::XChaCha20Poly1305,
        &params,
        b"dispatch-xchacha-plaintext",
    )
    .expect_err("XChaCha20-Poly1305 must reject a 12-byte nonce");

    match err {
        AlgorithmError::Crypto(CryptoError::InvalidAeadNonceLength { expected, actual }) => {
            assert_eq!(expected, 24);
            assert_eq!(actual, nonce.len());
        }
        _ => panic!("unexpected error variant for invalid nonce length"),
    }
}
