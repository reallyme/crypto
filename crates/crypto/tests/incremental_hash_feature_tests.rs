// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(
    feature = "operation-response",
    any(feature = "sha2", feature = "sha3")
))]
#![allow(clippy::unwrap_used, missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithm,
    __buffa::oneof::crypto_error::Error as ProtoError,
    __buffa::oneof::crypto_operation_request::Operation,
    __buffa::oneof::crypto_operation_response::Outcome, CryptoAlgorithmIdentifier,
    CryptoHashRequest, CryptoIncrementalHashFinalizeRequest, CryptoIncrementalHashStartRequest,
    CryptoOperationRequest, HashAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use reallyme_crypto::operation_contract::incremental_hash::IncrementalHash;

#[test]
fn unspecified_and_unknown_selectors_match_one_shot_provider_errors() {
    for selector in [0, 1, -1, i32::MAX] {
        let algorithm = EnumValue::from(selector);
        let incremental_error =
            IncrementalHash::start(&CryptoIncrementalHashStartRequest { algorithm })
                .err()
                .unwrap();
        assert_eq!(
            incremental_error,
            CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM
        );

        // Compare the actual serialized one-shot boundary as well as the
        // reason code: SDKs distinguish provider errors from primitive errors.
        let one_shot = CryptoOperationRequest {
            operation: Some(Operation::Hash(Box::new(CryptoHashRequest {
                algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                    algorithm: Some(ProtoAlgorithm::Hash(algorithm)),
                }),
                input: Vec::new().into(),
            }))),
        };
        let encoded = reallyme_crypto::operation_contract::process_operation_response(
            &one_shot.encode_to_vec(),
        );
        let response = decode_operation_response(&encoded).unwrap();
        assert!(matches!(
            response.outcome.as_ref(),
            Some(Outcome::Error(error)) if matches!(
                error.error.as_ref(),
                Some(ProtoError::Provider(provider))
                    if provider.reason.as_known() == Some(incremental_error.reason())
            )
        ));
    }
}

#[test]
fn algorithm_availability_follows_enabled_leaf_features() {
    for (algorithm, enabled) in [
        (
            HashAlgorithm::HASH_ALGORITHM_SHA2_256,
            cfg!(feature = "sha2"),
        ),
        (
            HashAlgorithm::HASH_ALGORITHM_SHA3_256,
            cfg!(feature = "sha3"),
        ),
    ] {
        let request = CryptoIncrementalHashStartRequest {
            algorithm: EnumValue::from(algorithm),
        };
        let result = IncrementalHash::start(&request);
        if enabled {
            let digest = result
                .unwrap()
                .finalize(&CryptoIncrementalHashFinalizeRequest::default())
                .unwrap();
            assert_eq!(digest.digest.as_slice().len(), 32);
        } else {
            assert!(matches!(
                result,
                Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            ));
        }
    }
}
