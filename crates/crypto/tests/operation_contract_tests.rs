// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for the operation-contract module boundary.

#![cfg(feature = "operation-response")]
#![allow(clippy::expect_used)]
#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHashRequest, CryptoOperationRequest,
    HashAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use crypto_proto::wire::{CryptoWireError, CryptoWireErrorBranch};

#[test]
fn operation_contract_processes_binary_requests() {
    let request_bytes = hash_operation_request().encode_to_vec();

    let output = reallyme_crypto::operation_contract::process_operation_response(&request_bytes);
    let response = decode_operation_response(output.as_slice()).expect("response decodes");
    assert!(response.outcome.is_some());
}

#[test]
fn operation_contract_processes_proto_json_requests() {
    let request_json = br#"{
        "hash": {
            "algorithm": { "hash": "HASH_ALGORITHM_SHA2_256" },
            "input": "YWJj"
        }
    }"#;

    let output = reallyme_crypto::operation_contract::process_operation_response_json(request_json);
    let response = decode_operation_response(output.as_slice()).expect("response decodes");
    assert!(response.outcome.is_some());
}

#[test]
fn operation_contract_json_returns_typed_provider_error_for_secret_operation() {
    let request_json = br#"{"aeadSeal":{"key":"\u0045""#;
    let output = reallyme_crypto::operation_contract::process_operation_response_json(request_json);
    let response = decode_operation_response(output.as_slice()).expect("response decodes");
    assert!(matches!(
        &response.outcome,
        Some(CryptoOperationOutcome::Error(_))
    ));
    let error = match response.outcome {
        Some(CryptoOperationOutcome::Error(error)) => CryptoWireError::from_proto(&error),
        _ => return,
    };

    assert_eq!(error.branch(), CryptoWireErrorBranch::Provider);
    assert_eq!(
        error.known_reason(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND)
    );
}

fn hash_operation_request() -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::Hash(Box::new(CryptoHashRequest {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(
                    HashAlgorithm::HASH_ALGORITHM_SHA2_256,
                ))),
                __buffa_unknown_fields: Default::default(),
            }),
            input: b"abc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}
