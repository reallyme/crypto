// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "aes-kw")]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Operation-owner tests for AES-KW routes.

use crypto_core::{CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation};
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

struct KeyWrapCase {
    algorithm: KeyWrapAlgorithm,
    kek_len: usize,
}

const KEY_WRAP_CASES: &[KeyWrapCase] = &[
    KeyWrapCase {
        algorithm: KeyWrapAlgorithm::Aes128Kw,
        kek_len: reallyme_crypto::aes_kw::AES_128_KW_KEK_LENGTH,
    },
    KeyWrapCase {
        algorithm: KeyWrapAlgorithm::Aes192Kw,
        kek_len: reallyme_crypto::aes_kw::AES_192_KW_KEK_LENGTH,
    },
    KeyWrapCase {
        algorithm: KeyWrapAlgorithm::Aes256Kw,
        kek_len: reallyme_crypto::aes_kw::AES_256_KW_KEK_LENGTH,
    },
];

#[test]
fn key_wrap_operation_matches_rfc_3394_known_answers() {
    let cases = [
        (
            KeyWrapAlgorithm::Aes128Kw,
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
        ),
        (
            KeyWrapAlgorithm::Aes192Kw,
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
        ),
        (
            KeyWrapAlgorithm::Aes256Kw,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
            "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
        ),
    ];

    for (algorithm, kek, key_data, expected_wrapped) in cases {
        let kek = hex(kek);
        let key_data = hex(key_data);
        let expected_wrapped = hex(expected_wrapped);
        let wrapped = reallyme_crypto::operations::key_wrap::wrap_key(algorithm, &kek, &key_data)
            .expect("RFC 3394 wrap succeeds");
        assert_eq!(wrapped.as_bytes(), expected_wrapped);

        let unwrapped =
            reallyme_crypto::operations::key_wrap::unwrap_key(algorithm, &kek, &expected_wrapped)
                .expect("RFC 3394 unwrap succeeds");
        assert_eq!(unwrapped.as_bytes(), key_data);
    }
}

#[test]
fn key_wrap_operation_matches_root_facades() {
    let key_data = bytes(32, 0x70);

    for case in KEY_WRAP_CASES {
        let kek = bytes(case.kek_len, 0x20);
        let operation_wrapped =
            reallyme_crypto::operations::key_wrap::wrap_key(case.algorithm, &kek, &key_data)
                .expect("operation wrap succeeds");
        let root_wrapped = root_wrap(case.algorithm, &kek, &key_data);

        assert_eq!(operation_wrapped.as_bytes(), root_wrapped.as_bytes());

        let operation_unwrapped = reallyme_crypto::operations::key_wrap::unwrap_key(
            case.algorithm,
            &kek,
            operation_wrapped.as_bytes(),
        )
        .expect("operation unwrap succeeds");
        let root_unwrapped = root_unwrap(case.algorithm, &kek, root_wrapped.as_bytes());

        assert_eq!(operation_unwrapped.as_bytes(), key_data);
        assert_eq!(root_unwrapped.as_bytes(), key_data);
    }
}

#[test]
fn key_wrap_operation_reports_stable_failure_reasons_for_malicious_inputs() {
    let key_data = bytes(32, 0x33);

    for case in KEY_WRAP_CASES {
        let kek = bytes(case.kek_len, 0x44);
        let wrapped =
            reallyme_crypto::operations::key_wrap::wrap_key(case.algorithm, &kek, &key_data)
                .expect("operation wrap succeeds");
        let mut tampered = wrapped.as_bytes().to_vec();
        let first = tampered.first_mut().expect("wrapped key is not empty");
        *first ^= 0x01;

        assert_eq!(
            reallyme_crypto::operations::key_wrap::wrap_key(case.algorithm, &[], &key_data),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::key_wrap::wrap_key(case.algorithm, &kek, &[0x11; 8]),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidLength,
            })
        );
        assert_operation_error(
            reallyme_crypto::operations::key_wrap::unwrap_key(case.algorithm, &kek, &[0x22; 8])
                .err(),
            PrimitiveErrorReason::InvalidLength,
        );
        assert_operation_error(
            reallyme_crypto::operations::key_wrap::unwrap_key(case.algorithm, &kek, &tampered)
                .err(),
            PrimitiveErrorReason::VerificationFailed,
        );
    }
}

#[test]
fn root_facades_preserve_historical_key_wrap_error_shapes() {
    let kek = [0x42u8; reallyme_crypto::aes_kw::AES_256_KW_KEK_LENGTH];
    let key_data = bytes(32, 0x55);
    let typed_kek = reallyme_crypto::aes_kw::Aes256KwKek::from_slice(&kek).expect("KEK is valid");
    let wrapped =
        reallyme_crypto::aes_kw::wrap_key(&typed_kek, &key_data).expect("root wrap succeeds");
    let mut tampered = wrapped.as_bytes().to_vec();
    let first = tampered.first_mut().expect("wrapped key is not empty");
    *first ^= 0x80;

    assert!(matches!(
        reallyme_crypto::aes_kw::wrap_key(&typed_kek, &[0x11; 8]),
        Err(CryptoError::KeyWrap {
            operation: KeyWrapOperation::Wrap,
            kind: KeyWrapFailureKind::InvalidPlaintextLength,
            ..
        })
    ));
    assert!(matches!(
        reallyme_crypto::aes_kw::unwrap_key(&typed_kek, &[0x22; 8]),
        Err(CryptoError::KeyWrap {
            operation: KeyWrapOperation::Unwrap,
            kind: KeyWrapFailureKind::InvalidWrappedLength,
            ..
        })
    ));
    assert!(matches!(
        reallyme_crypto::aes_kw::unwrap_key(&typed_kek, &tampered),
        Err(CryptoError::KeyWrap {
            operation: KeyWrapOperation::Unwrap,
            kind: KeyWrapFailureKind::IntegrityCheckFailed,
            ..
        })
    ));
}

#[test]
fn key_wrap_operation_enforces_minimum_maximum_and_oversized_lengths() {
    let maximum_plaintext = vec![0x5au8; reallyme_crypto::aes_kw::AES_KW_MAX_KEY_DATA_LENGTH];
    let oversized_plaintext_length = reallyme_crypto::aes_kw::AES_KW_MAX_KEY_DATA_LENGTH
        .checked_add(reallyme_crypto::aes_kw::AES_KW_BLOCK_LENGTH)
        .expect("test constants fit usize");
    let maximum_wrapped_length = reallyme_crypto::aes_kw::AES_KW_MAX_KEY_DATA_LENGTH
        .checked_add(reallyme_crypto::aes_kw::AES_KW_INTEGRITY_CHECK_LENGTH)
        .expect("test constants fit usize");
    let oversized_wrapped_length = maximum_wrapped_length
        .checked_add(reallyme_crypto::aes_kw::AES_KW_BLOCK_LENGTH)
        .expect("test constants fit usize");
    let oversized_plaintext = vec![0x5au8; oversized_plaintext_length];
    let oversized_wrapped = vec![0x5au8; oversized_wrapped_length];

    for case in KEY_WRAP_CASES {
        let kek = bytes(case.kek_len, 0x31);
        let minimum_plaintext = [0x5au8; reallyme_crypto::aes_kw::AES_KW_MIN_KEY_DATA_LENGTH];
        let minimum_wrapped = reallyme_crypto::operations::key_wrap::wrap_key(
            case.algorithm,
            &kek,
            &minimum_plaintext,
        )
        .expect("minimum plaintext length is accepted");
        assert_eq!(
            reallyme_crypto::operations::key_wrap::unwrap_key(
                case.algorithm,
                &kek,
                minimum_wrapped.as_bytes(),
            )
            .expect("minimum wrapped length is accepted")
            .as_bytes(),
            minimum_plaintext
        );

        let maximum_wrapped = reallyme_crypto::operations::key_wrap::wrap_key(
            case.algorithm,
            &kek,
            &maximum_plaintext,
        )
        .expect("maximum plaintext length is accepted");
        assert_eq!(
            reallyme_crypto::operations::key_wrap::unwrap_key(
                case.algorithm,
                &kek,
                maximum_wrapped.as_bytes(),
            )
            .expect("maximum wrapped length is accepted")
            .as_bytes(),
            maximum_plaintext
        );

        assert_eq!(
            reallyme_crypto::operations::key_wrap::wrap_key(
                case.algorithm,
                &kek,
                &oversized_plaintext,
            ),
            Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidLength,
            })
        );
        assert_operation_error(
            reallyme_crypto::operations::key_wrap::unwrap_key(
                case.algorithm,
                &kek,
                &oversized_wrapped,
            )
            .err(),
            PrimitiveErrorReason::InvalidLength,
        );
    }
}

#[test]
fn operation_unwrapped_key_transfers_its_zeroizing_allocation() {
    let kek = [0x42u8; reallyme_crypto::aes_kw::AES_256_KW_KEK_LENGTH];
    let wrapped = reallyme_crypto::operations::key_wrap::wrap_key(
        KeyWrapAlgorithm::Aes256Kw,
        &kek,
        &[0x24u8; 32],
    )
    .expect("wrap succeeds");
    let unwrapped = reallyme_crypto::operations::key_wrap::unwrap_key(
        KeyWrapAlgorithm::Aes256Kw,
        &kek,
        wrapped.as_bytes(),
    )
    .expect("unwrap succeeds");
    let allocation = unwrapped.as_bytes().as_ptr();

    let owned = unwrapped.into_zeroizing();

    assert_eq!(owned.as_ptr(), allocation);
}

fn root_wrap(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
    key_data: &[u8],
) -> reallyme_crypto::aes_kw::AesKwWrappedKey {
    match algorithm {
        KeyWrapAlgorithm::Aes128Kw => {
            let kek = reallyme_crypto::aes_kw::Aes128KwKek::from_slice(kek).expect("KEK is valid");
            reallyme_crypto::aes_kw::wrap_key_aes128(&kek, key_data).expect("root wrap succeeds")
        }
        KeyWrapAlgorithm::Aes192Kw => {
            let kek = reallyme_crypto::aes_kw::Aes192KwKek::from_slice(kek).expect("KEK is valid");
            reallyme_crypto::aes_kw::wrap_key_aes192(&kek, key_data).expect("root wrap succeeds")
        }
        KeyWrapAlgorithm::Aes256Kw => {
            let kek = reallyme_crypto::aes_kw::Aes256KwKek::from_slice(kek).expect("KEK is valid");
            reallyme_crypto::aes_kw::wrap_key_aes256(&kek, key_data).expect("root wrap succeeds")
        }
        _ => panic!("test case uses unsupported future AES-KW algorithm"),
    }
}

fn root_unwrap(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
    wrapped_key: &[u8],
) -> reallyme_crypto::aes_kw::AesKwKeyData {
    match algorithm {
        KeyWrapAlgorithm::Aes128Kw => {
            let kek = reallyme_crypto::aes_kw::Aes128KwKek::from_slice(kek).expect("KEK is valid");
            reallyme_crypto::aes_kw::unwrap_key_aes128(&kek, wrapped_key)
                .expect("root unwrap succeeds")
        }
        KeyWrapAlgorithm::Aes192Kw => {
            let kek = reallyme_crypto::aes_kw::Aes192KwKek::from_slice(kek).expect("KEK is valid");
            reallyme_crypto::aes_kw::unwrap_key_aes192(&kek, wrapped_key)
                .expect("root unwrap succeeds")
        }
        KeyWrapAlgorithm::Aes256Kw => {
            let kek = reallyme_crypto::aes_kw::Aes256KwKek::from_slice(kek).expect("KEK is valid");
            reallyme_crypto::aes_kw::unwrap_key_aes256(&kek, wrapped_key)
                .expect("root unwrap succeeds")
        }
        _ => panic!("test case uses unsupported future AES-KW algorithm"),
    }
}

fn assert_operation_error(error: Option<OperationError>, reason: PrimitiveErrorReason) {
    assert_eq!(
        error,
        Some(OperationError::Primitive { reason }),
        "unexpected key-wrap operation error"
    );
}

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index).expect("test length fits in u8")))
        .collect()
}

fn hex(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "hex fixture has complete bytes"
    );
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let pair = core::str::from_utf8(chunk).expect("hex fixture is UTF-8");
            u8::from_str_radix(pair, 16).expect("hex fixture is valid")
        })
        .collect()
}
