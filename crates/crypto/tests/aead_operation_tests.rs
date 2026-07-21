// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305",
    feature = "dispatch"
))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Operation-owner tests for AEAD routes.

use crypto_core::{AeadAlgorithm, AeadFailureKind, CryptoError};
use reallyme_crypto::dispatch::AeadParams;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

const STANDARD_NONCE_LEN: usize = 12;
const XCHACHA_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;

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
fn aead_operation_matches_root_primitive_and_dispatch_facades() {
    let aad = b"reallyme AEAD aad";
    let plaintext = b"reallyme AEAD plaintext";

    for case in AEAD_CASES {
        let key = bytes(case.key_len, 0x10);
        let nonce = bytes(case.nonce_len, 0xa0);

        let operation_ciphertext =
            reallyme_crypto::operations::aead::seal(case.algorithm, &key, &nonce, aad, plaintext)
                .expect("AEAD operation seal succeeds");
        let root_ciphertext = root_seal(case.algorithm, &key, &nonce, aad, plaintext);
        let dispatch_params = AeadParams {
            key: &key,
            nonce: &nonce,
            aad,
        };
        let dispatch_ciphertext =
            reallyme_crypto::dispatch::aead_encrypt(case.algorithm, &dispatch_params, plaintext)
                .expect("AEAD dispatch seal succeeds");

        assert_eq!(operation_ciphertext, root_ciphertext);
        assert_eq!(operation_ciphertext, dispatch_ciphertext);

        let operation_plaintext = reallyme_crypto::operations::aead::open(
            case.algorithm,
            &key,
            &nonce,
            aad,
            &operation_ciphertext,
        )
        .expect("AEAD operation open succeeds");
        let dispatch_plaintext = reallyme_crypto::dispatch::aead_decrypt(
            case.algorithm,
            &dispatch_params,
            &operation_ciphertext,
        )
        .expect("AEAD dispatch open succeeds");

        assert_eq!(operation_plaintext.as_slice(), plaintext);
        assert_eq!(dispatch_plaintext.as_slice(), plaintext);
    }
}

#[test]
fn aead_operation_reports_stable_failure_reasons_for_malicious_inputs() {
    let aad = b"aad";
    let plaintext = b"plaintext";

    for case in AEAD_CASES {
        let key = bytes(case.key_len, 0x20);
        let nonce = bytes(case.nonce_len, 0x30);
        let ciphertext =
            reallyme_crypto::operations::aead::seal(case.algorithm, &key, &nonce, aad, plaintext)
                .expect("AEAD operation seal succeeds");

        let mut tampered_ciphertext = ciphertext.clone();
        let first = tampered_ciphertext
            .first_mut()
            .expect("ciphertext with tag is not empty");
        *first ^= 0x01;

        let mut wrong_key = key.clone();
        let first = wrong_key.first_mut().expect("key is not empty");
        *first ^= 0x80;

        let mut wrong_nonce = nonce.clone();
        let first = wrong_nonce.first_mut().expect("nonce is not empty");
        *first ^= 0x40;

        assert_eq!(
            reallyme_crypto::operations::aead::seal(case.algorithm, &[], &nonce, aad, plaintext),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::aead::seal(
                case.algorithm,
                &key,
                &nonce[..case.nonce_len - 1],
                aad,
                plaintext,
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidLength,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::aead::open(
                case.algorithm,
                &key,
                &nonce,
                aad,
                &ciphertext[..AEAD_TAG_LEN - 1],
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidLength,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::aead::open(
                case.algorithm,
                &key,
                &nonce,
                b"wrong aad",
                &ciphertext,
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::aead::open(
                case.algorithm,
                &wrong_key,
                &nonce,
                aad,
                &ciphertext,
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::aead::open(
                case.algorithm,
                &key,
                &wrong_nonce,
                aad,
                &ciphertext,
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::aead::open(
                case.algorithm,
                &key,
                &nonce,
                aad,
                &tampered_ciphertext,
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            })
        );
    }
}

#[test]
fn root_dispatch_facade_preserves_historical_aead_error_shapes() {
    let key = bytes(16, 0x44);
    let nonce = bytes(STANDARD_NONCE_LEN, 0x55);
    let aad = b"aad";
    let plaintext = b"plaintext";
    let params = AeadParams {
        key: &key,
        nonce: &nonce,
        aad,
    };
    let ciphertext =
        reallyme_crypto::dispatch::aead_encrypt(AeadAlgorithm::Aes128Gcm, &params, plaintext)
            .expect("dispatch AEAD seal succeeds");

    let short_nonce = bytes(STANDARD_NONCE_LEN - 1, 0x55);
    let short_nonce_params = AeadParams {
        key: &key,
        nonce: &short_nonce,
        aad,
    };
    assert!(matches!(
        reallyme_crypto::dispatch::aead_encrypt(
            AeadAlgorithm::Aes128Gcm,
            &short_nonce_params,
            plaintext,
        ),
        Err(reallyme_crypto::dispatch::AlgorithmError::Crypto(
            CryptoError::InvalidAeadNonceLength {
                expected: STANDARD_NONCE_LEN,
                actual: 11,
            }
        ))
    ));

    assert!(matches!(
        reallyme_crypto::dispatch::aead_decrypt(
            AeadAlgorithm::Aes128Gcm,
            &params,
            &ciphertext[..AEAD_TAG_LEN - 1],
        ),
        Err(reallyme_crypto::dispatch::AlgorithmError::Crypto(
            CryptoError::InvalidCiphertextLength {
                minimum: AEAD_TAG_LEN,
                actual: 15,
            }
        ))
    ));

    let mut tampered_ciphertext = ciphertext.clone();
    let first = tampered_ciphertext
        .first_mut()
        .expect("ciphertext with tag is not empty");
    *first ^= 0x02;
    assert!(matches!(
        reallyme_crypto::dispatch::aead_decrypt(
            AeadAlgorithm::Aes128Gcm,
            &params,
            &tampered_ciphertext,
        ),
        Err(reallyme_crypto::dispatch::AlgorithmError::Crypto(
            CryptoError::AeadDecrypt {
                kind: AeadFailureKind::AuthenticationFailed,
                ..
            }
        ))
    ));
}

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index).expect("test vector length fits in u8")))
        .collect()
}

fn root_seal(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => {
            let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(key)
                .expect("AES-128-GCM key is valid");
            let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(nonce)
                .expect("AES-128-GCM nonce is valid");
            reallyme_crypto::aes::encrypt_aes128_gcm(
                &reallyme_crypto::aes::Aes128GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .expect("AES-128-GCM root seal succeeds")
            .into_vec()
        }
        AeadAlgorithm::Aes192Gcm => {
            let key = reallyme_crypto::aes::Aes192GcmKey::from_slice(key)
                .expect("AES-192-GCM key is valid");
            let nonce = reallyme_crypto::aes::Aes192GcmNonce::from_slice(nonce)
                .expect("AES-192-GCM nonce is valid");
            reallyme_crypto::aes::encrypt_aes192_gcm(
                &reallyme_crypto::aes::Aes192GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .expect("AES-192-GCM root seal succeeds")
            .into_vec()
        }
        AeadAlgorithm::Aes256Gcm => {
            let key = reallyme_crypto::aes::Aes256GcmKey::from_slice(key)
                .expect("AES-256-GCM key is valid");
            let nonce = reallyme_crypto::aes::Aes256GcmNonce::from_slice(nonce)
                .expect("AES-256-GCM nonce is valid");
            reallyme_crypto::aes::encrypt(&reallyme_crypto::aes::EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
            .expect("AES-256-GCM root seal succeeds")
            .into_vec()
        }
        AeadAlgorithm::Aes256GcmSiv => {
            let key = reallyme_crypto::aes_gcm_siv::Aes256GcmSivKey::from_slice(key)
                .expect("AES-256-GCM-SIV key is valid");
            let nonce = reallyme_crypto::aes_gcm_siv::Aes256GcmSivNonce::from_slice(nonce)
                .expect("AES-256-GCM-SIV nonce is valid");
            reallyme_crypto::aes_gcm_siv::encrypt(&reallyme_crypto::aes_gcm_siv::EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
            .expect("AES-256-GCM-SIV root seal succeeds")
            .into_vec()
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let key = reallyme_crypto::chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key)
                .expect("ChaCha20-Poly1305 key is valid");
            let nonce =
                reallyme_crypto::chacha20_poly1305::ChaCha20Poly1305Nonce::from_slice(nonce)
                    .expect("ChaCha20-Poly1305 nonce is valid");
            reallyme_crypto::chacha20_poly1305::encrypt(
                &reallyme_crypto::chacha20_poly1305::EncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .expect("ChaCha20-Poly1305 root seal succeeds")
            .into_vec()
        }
        AeadAlgorithm::XChaCha20Poly1305 => {
            let key = reallyme_crypto::chacha20_poly1305::ChaCha20Poly1305Key::from_slice(key)
                .expect("XChaCha20-Poly1305 key is valid");
            let nonce =
                reallyme_crypto::chacha20_poly1305::XChaCha20Poly1305Nonce::from_slice(nonce)
                    .expect("XChaCha20-Poly1305 nonce is valid");
            reallyme_crypto::chacha20_poly1305::encrypt_xchacha20_poly1305(
                &reallyme_crypto::chacha20_poly1305::XChaCha20Poly1305EncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .expect("XChaCha20-Poly1305 root seal succeeds")
            .into_vec()
        }
    }
}
