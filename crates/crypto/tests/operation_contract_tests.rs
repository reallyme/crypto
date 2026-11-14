// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    let error = match response.outcome.as_ref() {
        Some(CryptoOperationOutcome::Error(error)) => CryptoWireError::from_proto(error),
        _ => return,
    };

    assert_eq!(error.branch(), CryptoWireErrorBranch::Provider);
    assert_eq!(
        error.known_reason(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND)
    );
}

#[test]
fn proto_json_open_selectors_serialize_only_the_pre_dispatch_policy_error() {
    // Canonical wire bytes from crypto.proto for the provider policy error.
    // Check the entire envelope so oneof decoding cannot mask a result field.
    const EXPECTED: &[u8] = &[0x12, 0x05, 0x12, 0x03, 0x08, 0xc9, 0x01];
    for request in [
        br#" { "aeadOpen": {} }"#.as_slice(),
        br#" { "hpkeOpen": {} }"#.as_slice(),
        br#" { "hpkePskOpen": {} }"#.as_slice(),
        br#"{"aeadOpen":{"key":"\u0041""#.as_slice(),
        br#"{"hpkeOpen":{"recipientSecretKey":"\u0041""#.as_slice(),
        br#"{"hpkePskOpen":{"psk":"\u0041""#.as_slice(),
    ] {
        let output = reallyme_crypto::operation_contract::process_operation_response_json(request);
        assert_eq!(output.as_slice(), EXPECTED);
    }

    // Aliases and additional members must fail before a generated oneof can
    // normalize the selector or discard an earlier operation.
    for request in [
        br#"{"aead_open":{}}"#.as_slice(),
        br#"{"hpke_open":{}}"#.as_slice(),
        br#"{"hpke_psk_open":{}}"#.as_slice(),
        br#"{"aead\u004fpen":{}}"#.as_slice(),
        br#"{"hash":{},"hpkeOpen":{}}"#.as_slice(),
    ] {
        let output = reallyme_crypto::operation_contract::process_operation_response_json(request);
        let response = decode_operation_response(&output).expect("response decodes");
        let error = match response.outcome.as_ref() {
            Some(CryptoOperationOutcome::Error(error)) => Some(CryptoWireError::from_proto(error)),
            _ => None,
        };
        assert_eq!(
            error.map(CryptoWireError::branch),
            Some(CryptoWireErrorBranch::Primitive)
        );
        assert_eq!(
            error.and_then(CryptoWireError::known_reason),
            Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON)
        );
    }
}

fn hash_operation_request() -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::Hash(Box::new(CryptoHashRequest {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(
                    HashAlgorithm::HASH_ALGORITHM_SHA2_256,
                ))),
            }),
            input: b"abc".to_vec().into(),
        }))),
    }
}
