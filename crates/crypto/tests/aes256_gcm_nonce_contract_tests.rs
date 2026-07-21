// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]
#![allow(missing_docs)]
#![cfg(all(feature = "aes", feature = "native"))]

use reallyme_crypto::aes256_gcm::{
    aes256_gcm_decrypt, aes256_gcm_encrypt, Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag,
    AES_256_GCM_KEY_LEN, AES_256_GCM_NONCE_LEN, AES_256_GCM_TAG_LEN,
};
use reallyme_crypto::CryptoError;

const KEY_BYTES: [u8; AES_256_GCM_KEY_LEN] = [0x41; AES_256_GCM_KEY_LEN];
const NONCE_BYTES: [u8; AES_256_GCM_NONCE_LEN] = [0x24; AES_256_GCM_NONCE_LEN];
const AAD: &[u8] = b"MLS protocol context";
const PLAINTEXT: &[u8] = b"application message";

#[test]
fn facade_enforces_exact_key_and_nonce_lengths() {
    for length in [0_usize, 31, 33] {
        let bytes = vec![0_u8; length];
        assert!(matches!(
            Aes256GcmKey::from_slice(&bytes),
            Err(CryptoError::InvalidAeadKeyLength { expected, actual })
                if expected == AES_256_GCM_KEY_LEN && actual == length
        ));
    }

    for length in [0_usize, 11, 13] {
        let bytes = vec![0_u8; length];
        assert!(matches!(
            Aes256GcmNonce::from_slice(&bytes),
            Err(CryptoError::InvalidAeadNonceLength { expected, actual })
                if expected == AES_256_GCM_NONCE_LEN && actual == length
        ));
    }
}

#[test]
fn facade_appends_and_requires_the_full_authentication_tag() {
    let key = key();
    let nonce = nonce();
    let ciphertext =
        aes256_gcm_encrypt(&key, nonce, AAD, PLAINTEXT).expect("valid encryption must succeed");
    assert_eq!(
        ciphertext.as_bytes().len(),
        PLAINTEXT.len() + AES_256_GCM_TAG_LEN
    );

    for length in 0..AES_256_GCM_TAG_LEN {
        assert!(matches!(
            CiphertextWithTag::from_vec(vec![0_u8; length]),
            Err(CryptoError::InvalidCiphertextLength { minimum, actual })
                if minimum == AES_256_GCM_TAG_LEN && actual == length
        ));
    }
}

#[test]
fn facade_rejects_wrong_key_nonce_and_aad() {
    let key = key();
    let nonce = nonce();
    let ciphertext =
        aes256_gcm_encrypt(&key, nonce, AAD, PLAINTEXT).expect("valid encryption must succeed");
    let wrong_key = Aes256GcmKey::from_slice(&[0x42; AES_256_GCM_KEY_LEN])
        .expect("test key has the required length");
    let wrong_nonce = Aes256GcmNonce::from_slice(&[0x25; AES_256_GCM_NONCE_LEN])
        .expect("test nonce has the required length");

    assert_authentication_failure(aes256_gcm_decrypt(&wrong_key, nonce, AAD, &ciphertext));
    assert_authentication_failure(aes256_gcm_decrypt(&key, wrong_nonce, AAD, &ciphertext));
    assert_authentication_failure(aes256_gcm_decrypt(
        &key,
        nonce,
        b"different context",
        &ciphertext,
    ));
}

#[test]
fn facade_rejects_independent_ciphertext_and_tag_modification() {
    let key = key();
    let nonce = nonce();
    let ciphertext =
        aes256_gcm_encrypt(&key, nonce, AAD, PLAINTEXT).expect("valid encryption must succeed");

    let mut modified_ciphertext = ciphertext.as_bytes().to_vec();
    modified_ciphertext[0] ^= 0x80;
    let modified_ciphertext = CiphertextWithTag::from_vec(modified_ciphertext)
        .expect("mutation preserves the ciphertext shape");
    assert_authentication_failure(aes256_gcm_decrypt(&key, nonce, AAD, &modified_ciphertext));

    let mut modified_tag = ciphertext.into_vec();
    let last = modified_tag
        .len()
        .checked_sub(1)
        .expect("authenticated ciphertext always contains a tag");
    modified_tag[last] ^= 0x01;
    let modified_tag =
        CiphertextWithTag::from_vec(modified_tag).expect("mutation preserves the tag shape");
    assert_authentication_failure(aes256_gcm_decrypt(&key, nonce, AAD, &modified_tag));
}

fn key() -> Aes256GcmKey {
    Aes256GcmKey::from_slice(&KEY_BYTES).expect("test key has the required length")
}

fn nonce() -> Aes256GcmNonce {
    Aes256GcmNonce::from_slice(&NONCE_BYTES).expect("test nonce has the required length")
}

fn assert_authentication_failure(result: Result<Vec<u8>, CryptoError>) {
    assert!(matches!(result, Err(CryptoError::AeadDecrypt { .. })));
}
