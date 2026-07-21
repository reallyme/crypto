// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, test_aes128_key, test_aes128_nonce, test_aes192_key, test_aes192_nonce,
    test_key, test_nonce, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest,
    Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, DecryptRequest, EncryptRequest,
    AES_128_GCM_TAG_LENGTH, AES_192_GCM_TAG_LENGTH, AES_256_GCM_TAG_LENGTH,
};

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
