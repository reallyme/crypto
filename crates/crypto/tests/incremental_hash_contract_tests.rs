// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(feature = "operation-response", feature = "sha2", feature = "sha3"))]
#![allow(clippy::unwrap_used, missing_docs)]

use buffa::{DecodeOptions, EnumValue, Message};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoIncrementalHashFinalizeRequest,
    CryptoIncrementalHashStartRequest, CryptoIncrementalHashUpdateRequest, HashAlgorithm,
};
use reallyme_crypto::operation_contract::incremental_hash::IncrementalHash;
use zeroize::Zeroize;

#[test]
fn generated_binary_requests_match_existing_digest_outputs() {
    for algorithm in [
        HashAlgorithm::HASH_ALGORITHM_SHA2_256,
        HashAlgorithm::HASH_ALGORITHM_SHA3_256,
    ] {
        let start = CryptoIncrementalHashStartRequest {
            algorithm: EnumValue::from(algorithm),
        };
        let decoded = DecodeOptions::new()
            .with_max_message_size(64)
            .reject_unknown_fields()
            .decode_from_slice::<CryptoIncrementalHashStartRequest>(&start.encode_to_vec())
            .unwrap();
        let mut context = IncrementalHash::start(&decoded).unwrap();
        for (input, expected_count) in [(b"a".as_slice(), 1), (b"", 1), (b"bc", 3)] {
            let request = CryptoIncrementalHashUpdateRequest {
                input: input.to_vec().into(),
            };
            let decoded = DecodeOptions::new()
                .with_max_message_size(64)
                .reject_unknown_fields()
                .decode_from_slice::<CryptoIncrementalHashUpdateRequest>(&request.encode_to_vec())
                .unwrap();
            assert_eq!(
                context.update(&decoded).unwrap().processed_bytes,
                expected_count
            );
        }
        let result = context
            .finalize(&CryptoIncrementalHashFinalizeRequest::default())
            .unwrap();
        assert_eq!(
            result.algorithm.as_option().unwrap().algorithm,
            Some(Algorithm::Hash(EnumValue::from(algorithm)))
        );
        let expected = if algorithm == HashAlgorithm::HASH_ALGORITHM_SHA2_256 {
            reallyme_crypto::sha2::digest(b"abc").into_bytes()
        } else {
            reallyme_crypto::sha3::digest(b"abc").into_bytes()
        };
        assert_eq!(result.digest.as_slice(), expected);
    }
}

#[test]
fn unspecified_unknown_and_unsupported_selectors_have_stable_reasons() {
    for (selector, reason) in [
        (0, CryptoError::PRIMITIVE_INVALID_PARAMETER),
        (i32::MAX, CryptoError::PRIMITIVE_INVALID_PARAMETER),
        (-1, CryptoError::PRIMITIVE_INVALID_PARAMETER),
        (110, CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    ] {
        let request = CryptoIncrementalHashStartRequest {
            algorithm: EnumValue::from(selector),
        };
        assert!(matches!(IncrementalHash::start(&request), Err(error) if error == reason));
    }
}

#[test]
fn malformed_and_oversized_generated_requests_are_rejected_before_use() {
    for bytes in [
        vec![0x0a, 0x80],
        vec![0x0a, 0xff, 0xff, 0xff, 0xff, 0x07],
        vec![0x12, 0],
    ] {
        assert!(DecodeOptions::new()
            .with_max_message_size(16)
            .reject_unknown_fields()
            .decode_from_slice::<CryptoIncrementalHashUpdateRequest>(&bytes)
            .is_err());
    }
    let request = CryptoIncrementalHashUpdateRequest {
        input: vec![0x5a; 64].into(),
    };
    assert!(DecodeOptions::new()
        .with_max_message_size(16)
        .reject_unknown_fields()
        .decode_from_slice::<CryptoIncrementalHashUpdateRequest>(&request.encode_to_vec())
        .is_err());
}

#[test]
fn generated_boundary_observes_native_context_invalidation() {
    for algorithm in [
        HashAlgorithm::HASH_ALGORITHM_SHA2_256,
        HashAlgorithm::HASH_ALGORITHM_SHA3_256,
    ] {
        let mut context = IncrementalHash::start(&CryptoIncrementalHashStartRequest {
            algorithm: EnumValue::from(algorithm),
        })
        .unwrap();
        context.zeroize();
        assert_eq!(
            context.update(&CryptoIncrementalHashUpdateRequest::default()),
            Err(CryptoError::BACKEND_INVALID_STATE)
        );
        assert_eq!(
            context.finalize(&CryptoIncrementalHashFinalizeRequest::default()),
            Err(CryptoError::BACKEND_INVALID_STATE)
        );
    }
}
