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
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    AES_128_GCM_TAG_LENGTH, AES_192_GCM_TAG_LENGTH, AES_256_GCM_TAG_LENGTH,
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

fn test_aes128_key() -> Aes128GcmKey {
    let key_bytes = [0x11u8; 16];
    Aes128GcmKey::from_slice(&key_bytes).expect("test key must be valid")
}

fn test_aes128_nonce() -> Aes128GcmNonce {
    let nonce_bytes = [0x22u8; 12];
    Aes128GcmNonce::from_slice(&nonce_bytes).expect("test nonce must be valid")
}

fn test_aes192_key() -> Aes192GcmKey {
    let key_bytes = [0x11u8; 24];
    Aes192GcmKey::from_slice(&key_bytes).expect("test key must be valid")
}

fn test_aes192_nonce() -> Aes192GcmNonce {
    let nonce_bytes = [0x22u8; 12];
    Aes192GcmNonce::from_slice(&nonce_bytes).expect("test nonce must be valid")
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
fn aes128_encrypt_then_decrypt_roundtrip() {
    let key = test_aes128_key();
    let nonce = test_aes128_nonce();
    let aad = b"associated-data";
    let plaintext = b"openid4vp direct_post.jwt payload";

    let encrypted = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    })
    .expect("encryption should succeed");

    let decrypted = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &encrypted,
    })
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes128_empty_plaintext_is_supported() {
    let key = test_aes128_key();
    let nonce = test_aes128_nonce();

    let encrypted = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad: b"",
        plaintext: b"",
    })
    .expect("encryption should succeed");

    assert_eq!(encrypted.as_bytes().len(), AES_128_GCM_TAG_LENGTH);

    let decrypted = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
        key: &key,
        nonce,
        aad: b"",
        ciphertext: &encrypted,
    })
    .expect("decryption should succeed");

    assert!(decrypted.is_empty());
}

#[test]
fn aes192_encrypt_then_decrypt_roundtrip() {
    let key = test_aes192_key();
    let nonce = test_aes192_nonce();
    let aad = b"associated-data";
    let plaintext = b"openid4vp direct_post.jwt payload";

    let encrypted = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad,
        plaintext,
    })
    .expect("encryption should succeed");

    let decrypted = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
        key: &key,
        nonce,
        aad,
        ciphertext: &encrypted,
    })
    .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes192_empty_plaintext_is_supported() {
    let key = test_aes192_key();
    let nonce = test_aes192_nonce();

    let encrypted = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad: b"",
        plaintext: b"",
    })
    .expect("encryption should succeed");

    assert_eq!(encrypted.as_bytes().len(), AES_192_GCM_TAG_LENGTH);

    let decrypted = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
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
fn invalid_aes128_key_length_is_rejected() {
    for actual in [0usize, 1, 15, 17, 32] {
        let input = vec![0u8; actual];
        let err = match Aes128GcmKey::from_slice(&input) {
            Err(err) => err,
            Ok(_) => panic!("invalid AES-128 key length {actual} must fail"),
        };

        match err {
            CryptoError::InvalidAeadKeyLength { expected, actual } => {
                assert_eq!(expected, 16);
                assert_eq!(actual, input.len());
            }
            _ => panic!("unexpected error variant for invalid key length"),
        }
    }
}

#[test]
fn invalid_aes192_key_length_is_rejected() {
    for actual in [0usize, 1, 23, 25, 32] {
        let input = vec![0u8; actual];
        let err = match Aes192GcmKey::from_slice(&input) {
            Err(err) => err,
            Ok(_) => panic!("invalid AES-192 key length {actual} must fail"),
        };

        match err {
            CryptoError::InvalidAeadKeyLength { expected, actual } => {
                assert_eq!(expected, 24);
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
fn invalid_aes128_nonce_length_is_rejected() {
    for actual in [0usize, 1, 11, 13, 24] {
        let input = vec![0u8; actual];
        let err = Aes128GcmNonce::from_slice(&input).expect_err("invalid nonce length must fail");

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
fn invalid_aes192_nonce_length_is_rejected() {
    for actual in [0usize, 1, 11, 13, 24] {
        let input = vec![0u8; actual];
        let err = Aes192GcmNonce::from_slice(&input).expect_err("invalid nonce length must fail");

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
fn aes128_decryption_fails_with_tampered_ciphertext() {
    let key = test_aes128_key();
    let nonce = test_aes128_nonce();

    let encrypted = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        plaintext: b"plaintext",
    })
    .expect("encryption should succeed");

    let mut tampered = encrypted.into_vec();
    tampered[0] ^= 0x80;

    let tampered = CiphertextWithTag::from_vec(tampered).expect("tampered bytes keep valid shape");

    let err = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
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
fn aes192_decryption_fails_with_tampered_ciphertext() {
    let key = test_aes192_key();
    let nonce = test_aes192_nonce();

    let encrypted = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        plaintext: b"plaintext",
    })
    .expect("encryption should succeed");

    let mut tampered = encrypted.into_vec();
    tampered[0] ^= 0x80;

    let tampered = CiphertextWithTag::from_vec(tampered).expect("tampered bytes keep valid shape");

    let err = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
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

#[test]
fn aes128_vector_encrypt_and_decrypt_matches() {
    for vector in vectors::all_aes128_regression_vectors() {
        let key = Aes128GcmKey::from_slice(&vector.key).expect("vector key must be valid");
        let nonce = Aes128GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");

        let encrypted = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            plaintext: &vector.plaintext,
        })
        .expect("vector encryption should succeed");

        assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

        let decrypted = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            ciphertext: &encrypted,
        })
        .expect("vector decryption should succeed");

        assert_eq!(decrypted, vector.plaintext);
    }
}

#[test]
fn aes192_vector_encrypt_and_decrypt_matches() {
    for vector in vectors::all_aes192_regression_vectors() {
        let key = Aes192GcmKey::from_slice(&vector.key).expect("vector key must be valid");
        let nonce = Aes192GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");

        let encrypted = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            plaintext: &vector.plaintext,
        })
        .expect("vector encryption should succeed");

        assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

        let decrypted = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            ciphertext: &encrypted,
        })
        .expect("vector decryption should succeed");

        assert_eq!(decrypted, vector.plaintext);
    }
}
