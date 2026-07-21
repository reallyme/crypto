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
#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

mod vectors;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn package_owned_wasm_matches_nist_vector() {
    for vector in vectors::all_regression_vectors() {
        let key = Aes256GcmKey::from_slice(&vector.key).expect("vector key must be valid");
        let nonce = Aes256GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");

        let encrypted = encrypt(&EncryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            plaintext: &vector.plaintext,
        })
        .expect("package-owned WASM encryption should succeed");
        assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

        let decrypted = decrypt(&DecryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            ciphertext: &encrypted,
        })
        .expect("package-owned WASM decryption should succeed");
        assert_eq!(decrypted, vector.plaintext);
    }
}

#[wasm_bindgen_test]
fn package_owned_wasm_matches_aes128_vectors() {
    for vector in vectors::all_aes128_regression_vectors() {
        let key = Aes128GcmKey::from_slice(&vector.key).expect("vector key must be valid");
        let nonce = Aes128GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");
        let encrypted = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            plaintext: &vector.plaintext,
        })
        .expect("package-owned WASM encryption should succeed");
        assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

        let decrypted = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            ciphertext: &encrypted,
        })
        .expect("package-owned WASM decryption should succeed");
        assert_eq!(decrypted, vector.plaintext);
    }
}

#[wasm_bindgen_test]
fn package_owned_wasm_matches_aes192_vectors() {
    for vector in vectors::all_aes192_regression_vectors() {
        let key = Aes192GcmKey::from_slice(&vector.key).expect("vector key must be valid");
        let nonce = Aes192GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");
        let encrypted = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            plaintext: &vector.plaintext,
        })
        .expect("package-owned WASM encryption should succeed");
        assert_eq!(encrypted.as_bytes(), vector.ciphertext_and_tag);

        let decrypted = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
            key: &key,
            nonce,
            aad: &vector.aad,
            ciphertext: &encrypted,
        })
        .expect("package-owned WASM decryption should succeed");
        assert_eq!(decrypted, vector.plaintext);
    }
}

#[wasm_bindgen_test]
fn package_owned_wasm_rejects_short_ciphertext_shape() {
    let result = CiphertextWithTag::from_vec(vec![0u8; 8]);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn package_owned_wasm_rejects_tampering() {
    let vector = vectors::nist_vector_case_13();
    let key = Aes256GcmKey::from_slice(&vector.key).expect("vector key must be valid");
    let nonce = Aes256GcmNonce::from_slice(&vector.nonce).expect("vector nonce must be valid");
    let mut tampered = vector.ciphertext_and_tag;
    tampered[0] ^= 1;
    let ciphertext = CiphertextWithTag::from_vec(tampered).expect("shape must remain valid");

    let result = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: &vector.aad,
        ciphertext: &ciphertext,
    });
    assert!(result.is_err());
}
