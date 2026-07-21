// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, vectors, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, DecryptRequest, EncryptRequest,
};

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
