// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
use crypto_aes256_gcm_siv::{
    decrypt, encrypt, Aes256GcmSivKey, Aes256GcmSivNonce, CiphertextWithTag, DecryptRequest,
    EncryptRequest, AES_256_GCM_SIV_TAG_LENGTH,
};
use crypto_core::CryptoError;

fn test_key() -> Option<Aes256GcmSivKey> {
    Aes256GcmSivKey::from_slice(&[0x11u8; 32]).ok()
}

fn test_nonce() -> Option<Aes256GcmSivNonce> {
    Aes256GcmSivNonce::from_slice(&[0x22u8; 12]).ok()
}

#[test]
fn encrypt_then_decrypt_roundtrip() {
    let key = match test_key() {
        Some(value) => value,
        None => return,
    };
    let nonce = match test_nonce() {
        Some(value) => value,
        None => return,
    };

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"associated-data",
        plaintext: b"top secret payload",
    });
    assert!(encrypted.is_ok());

    let encrypted = match encrypted {
        Ok(value) => value,
        Err(_) => return,
    };

    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"associated-data",
        ciphertext: &encrypted,
    });
    assert!(decrypted.is_ok());

    let decrypted = match decrypted {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(decrypted, b"top secret payload");
}

#[test]
fn empty_plaintext_is_supported() {
    let key = match test_key() {
        Some(value) => value,
        None => return,
    };
    let nonce = match test_nonce() {
        Some(value) => value,
        None => return,
    };

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"",
        plaintext: b"",
    });
    assert!(encrypted.is_ok());

    let encrypted = match encrypted {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(encrypted.as_bytes().len(), AES_256_GCM_SIV_TAG_LENGTH);

    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"",
        ciphertext: &encrypted,
    });
    assert!(decrypted.is_ok());

    let decrypted = match decrypted {
        Ok(value) => value,
        Err(_) => return,
    };

    assert!(decrypted.is_empty());
}

#[test]
fn invalid_key_length_is_rejected() {
    for actual in [0usize, 1, 31, 33, 64] {
        let input = vec![0u8; actual];
        let result = Aes256GcmSivKey::from_slice(&input);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidAeadKeyLength {
                expected: 32,
                actual,
            }) if actual == input.len()
        ));
    }
}

#[test]
fn invalid_nonce_length_is_rejected() {
    for actual in [0usize, 1, 11, 13, 24] {
        let input = vec![0u8; actual];
        let result = Aes256GcmSivNonce::from_slice(&input);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidAeadNonceLength {
                expected: 12,
                actual,
            }) if actual == input.len()
        ));
    }
}

#[test]
fn too_short_ciphertext_is_rejected() {
    for expected_actual in 0usize..AES_256_GCM_SIV_TAG_LENGTH {
        let result = CiphertextWithTag::from_vec(vec![0u8; expected_actual]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidCiphertextLength {
                minimum,
                actual,
            }) if minimum == AES_256_GCM_SIV_TAG_LENGTH && actual == expected_actual
        ));
    }
}

#[test]
fn decryption_fails_with_wrong_key() {
    let key = match test_key() {
        Some(value) => value,
        None => return,
    };
    let nonce = match test_nonce() {
        Some(value) => value,
        None => return,
    };

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        plaintext: b"plaintext",
    });
    assert!(encrypted.is_ok());

    let encrypted = match encrypted {
        Ok(value) => value,
        Err(_) => return,
    };

    let wrong_key = Aes256GcmSivKey::from_slice(&[0x33u8; 32]);
    assert!(wrong_key.is_ok());
    let wrong_key = match wrong_key {
        Ok(value) => value,
        Err(_) => return,
    };

    let result = decrypt(&DecryptRequest {
        key: &wrong_key,
        nonce,
        aad: b"aad",
        ciphertext: &encrypted,
    });
    assert!(matches!(result, Err(CryptoError::AeadDecrypt { .. })));
}

#[test]
fn decryption_fails_with_tampered_ciphertext() {
    let key = match test_key() {
        Some(value) => value,
        None => return,
    };
    let nonce = match test_nonce() {
        Some(value) => value,
        None => return,
    };

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        plaintext: b"plaintext",
    });
    assert!(encrypted.is_ok());

    let mut tampered = match encrypted {
        Ok(value) => value.into_vec(),
        Err(_) => return,
    };

    tampered[0] ^= 0x80;

    let tampered = CiphertextWithTag::from_vec(tampered);
    assert!(tampered.is_ok());
    let tampered = match tampered {
        Ok(value) => value,
        Err(_) => return,
    };

    let result = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"aad",
        ciphertext: &tampered,
    });
    assert!(matches!(result, Err(CryptoError::AeadDecrypt { .. })));
}

#[test]
fn decryption_fails_when_aad_does_not_match() {
    let key = match test_key() {
        Some(value) => value,
        None => return,
    };
    let nonce = match test_nonce() {
        Some(value) => value,
        None => return,
    };

    let encrypted = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: b"aad-one",
        plaintext: b"plaintext",
    });
    assert!(encrypted.is_ok());

    let encrypted = match encrypted {
        Ok(value) => value,
        Err(_) => return,
    };

    let result = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: b"aad-two",
        ciphertext: &encrypted,
    });
    assert!(matches!(result, Err(CryptoError::AeadDecrypt { .. })));
}
