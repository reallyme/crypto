// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, test_aes128_key, test_aes128_nonce, test_aes192_key, test_aes192_nonce,
    test_key, test_nonce, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, CryptoError, DecryptRequest, EncryptRequest,
    AES_256_GCM_TAG_LENGTH,
};

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
