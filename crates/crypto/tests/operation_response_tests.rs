// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "operation-response")]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Tests for the generated operation response boundary.

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHashRequest, CryptoOperationRequest,
    HashAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;

#[test]
fn operation_response_wraps_hash_result_in_generated_oneof() {
    let output = reallyme_crypto::operation_contract::process_operation_response(
        hash_operation_request().encode_to_vec().as_slice(),
    );
    let response = decode_operation_response(output.as_slice()).expect("response decodes");

    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::Hash(hash)) = result.result else {
        panic!("operation result did not contain the hash branch");
    };

    assert_eq!(
        hash.digest,
        vec![
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn operation_response_wraps_malformed_request_as_generated_error() {
    let output =
        reallyme_crypto::operation_contract::process_operation_response(&[0xff_u8, 0xff, 0xff]);
    let response = decode_operation_response(output.as_slice()).expect("response decodes");

    assert_primitive_error(
        response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
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

fn assert_primitive_error(
    response: crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationResponse,
    reason: CryptoErrorReason,
) {
    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Primitive(error)) = error.error else {
        panic!("operation error did not contain the primitive branch");
    };
    assert_eq!(error.reason.as_known(), Some(reason));
}
