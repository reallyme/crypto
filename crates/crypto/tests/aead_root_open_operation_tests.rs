// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Root primitive open parity tests for AEAD routes.

use crypto_core::AeadAlgorithm;

const STANDARD_NONCE_LEN: usize = 12;
const XCHACHA_NONCE_LEN: usize = 24;

struct AeadCase {
    algorithm: AeadAlgorithm,
    key_len: usize,
    nonce_len: usize,
}

const AEAD_CASES: &[AeadCase] = &[
    AeadCase {
        algorithm: AeadAlgorithm::Aes128Gcm,
        key_len: 16,
        nonce_len: STANDARD_NONCE_LEN,
    },
    AeadCase {
        algorithm: AeadAlgorithm::Aes192Gcm,
        key_len: 24,
        nonce_len: STANDARD_NONCE_LEN,
    },
    AeadCase {
        algorithm: AeadAlgorithm::Aes256Gcm,
        key_len: 32,
        nonce_len: STANDARD_NONCE_LEN,
    },
    AeadCase {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_len: 32,
        nonce_len: STANDARD_NONCE_LEN,
    },
    AeadCase {
        algorithm: AeadAlgorithm::ChaCha20Poly1305,
        key_len: 32,
        nonce_len: STANDARD_NONCE_LEN,
    },
    AeadCase {
        algorithm: AeadAlgorithm::XChaCha20Poly1305,
        key_len: 32,
        nonce_len: XCHACHA_NONCE_LEN,
    },
];

#[test]
fn root_primitive_open_matches_aead_operation_owner() {
    let aad = b"reallyme AEAD root open aad";
    let plaintext = b"reallyme AEAD root open plaintext";

    for case in AEAD_CASES {
        let key = bytes(case.key_len, 0x70);
        let nonce = bytes(case.nonce_len, 0x90);
        let ciphertext_with_tag =
            reallyme_crypto::operations::aead::seal(case.algorithm, &key, &nonce, aad, plaintext)
                .expect("AEAD operation seal succeeds");
        let operation_plaintext = reallyme_crypto::operations::aead::open(
            case.algorithm,
            &key,
            &nonce,
            aad,
            &ciphertext_with_tag,
        )
        .expect("AEAD operation open succeeds");

        assert_eq!(
            root_open(case.algorithm, &key, &nonce, aad, &ciphertext_with_tag),
            operation_plaintext.as_slice()
        );
    }
}

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index).expect("test vector length fits in u8")))
        .collect()
}

fn root_open(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Vec<u8> {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => {
            let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(key)
                .expect("AES-128-GCM key is valid");
            let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(nonce)
                .expect("AES-128-GCM nonce is valid");
            let ciphertext =
                reallyme_crypto::aes::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
                    .expect("AES-128-GCM ciphertext is valid");
            reallyme_crypto::aes::decrypt_aes128_gcm(
                &reallyme_crypto::aes::Aes128GcmDecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                },
            )
            .expect("AES-128-GCM root open succeeds")
        }
        AeadAlgorithm::Aes192Gcm => {
            let key = reallyme_crypto::aes::Aes192GcmKey::from_slice(key)
                .expect("AES-192-GCM key is valid");
            let nonce = reallyme_crypto::aes::Aes192GcmNonce::from_slice(nonce)
                .expect("AES-192-GCM nonce is valid");
            let ciphertext =
                reallyme_crypto::aes::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
                    .expect("AES-192-GCM ciphertext is valid");
            reallyme_crypto::aes::decrypt_aes192_gcm(
                &reallyme_crypto::aes::Aes192GcmDecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                },
            )
            .expect("AES-192-GCM root open succeeds")
        }
        AeadAlgorithm::Aes256Gcm => {
            let key = reallyme_crypto::aes::Aes256GcmKey::from_slice(key)
                .expect("AES-256-GCM key is valid");
            let nonce = reallyme_crypto::aes::Aes256GcmNonce::from_slice(nonce)
                .expect("AES-256-GCM nonce is valid");
            let ciphertext =
                reallyme_crypto::aes::CiphertextWithTag::from_vec(ciphertext_with_tag.to_vec())
                    .expect("AES-256-GCM ciphertext is valid");
            reallyme_crypto::aes::decrypt(&reallyme_crypto::aes::DecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
            .expect("AES-256-GCM root open succeeds")
        }
        AeadAlgorithm::Aes256GcmSiv => {
            let key = reallyme_crypto::aes_gcm_siv::Aes256GcmSivKey::from_slice(key)
                .expect("AES-256-GCM-SIV key is valid");
            let nonce = reallyme_crypto::aes_gcm_siv::Aes256GcmSivNonce::from_slice(nonce)
                .expect("AES-256-GCM-SIV nonce is valid");
            let ciphertext = reallyme_crypto::aes_gcm_siv::CiphertextWithTag::from_vec(
                ciphertext_with_tag.to_vec(),
            )
            .expect("AES-256-GCM-SIV ciphertext is valid");
            reallyme_crypto::aes_gcm_siv::decrypt(&reallyme_crypto::aes_gcm_siv::DecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
            .expect("AES-256-GCM-SIV root open succeeds")
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let key = reallyme_crypto::chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key)
                .expect("ChaCha20-Poly1305 key is valid");
            let nonce =
                reallyme_crypto::chacha20_poly1305::ChaCha20Poly1305Nonce::from_slice(nonce)
                    .expect("ChaCha20-Poly1305 nonce is valid");
            let ciphertext = reallyme_crypto::chacha20_poly1305::CiphertextWithTag::from_vec(
                ciphertext_with_tag.to_vec(),
            )
            .expect("ChaCha20-Poly1305 ciphertext is valid");
            reallyme_crypto::chacha20_poly1305::decrypt(
                &reallyme_crypto::chacha20_poly1305::DecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                },
            )
            .expect("ChaCha20-Poly1305 root open succeeds")
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            let key = reallyme_crypto::chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key)
                .expect("XChaCha20-Poly1305 key is valid");
            let nonce =
                reallyme_crypto::chacha20_poly1305::XChaCha20Poly1305Nonce::from_slice(nonce)
                    .expect("XChaCha20-Poly1305 nonce is valid");
            let ciphertext = reallyme_crypto::chacha20_poly1305::CiphertextWithTag::from_vec(
                ciphertext_with_tag.to_vec(),
            )
            .expect("XChaCha20-Poly1305 ciphertext is valid");
            reallyme_crypto::chacha20_poly1305::decrypt_xchacha20_poly1305(
                &reallyme_crypto::chacha20_poly1305::XChaCha20Poly1305DecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                },
            )
            .expect("XChaCha20-Poly1305 root open succeeds")
        }
    }
}
