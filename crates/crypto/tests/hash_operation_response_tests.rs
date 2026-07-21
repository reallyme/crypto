// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "operation-response")]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Generated operation-response coverage for hash semantics.

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoHashRequest, CryptoOperationRequest,
    CryptoOperationResponse, HashAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;

#[test]
fn operation_response_hash_branch_uses_operation_owner_for_sha3() {
    let output = reallyme_crypto::operation_contract::process_operation_response(
        hash_operation_request_for(HashAlgorithm::HASH_ALGORITHM_SHA3_512)
            .encode_to_vec()
            .as_slice(),
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
        reallyme_crypto::operations::hash::digest(reallyme_crypto::HashAlgorithm::Sha3_512, b"abc")
            .expect("operation hash succeeds")
    );
}

#[test]
fn operation_response_hash_unspecified_algorithm_is_provider_error() {
    let output = reallyme_crypto::operation_contract::process_operation_response(
        hash_operation_request_for(HashAlgorithm::HASH_ALGORITHM_UNSPECIFIED)
            .encode_to_vec()
            .as_slice(),
    );
    let response = decode_operation_response(output.as_slice()).expect("response decodes");

    assert_provider_error(
        response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

fn hash_operation_request_for(algorithm: HashAlgorithm) -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::Hash(Box::new(CryptoHashRequest {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(algorithm))),
                __buffa_unknown_fields: Default::default(),
            }),
            input: b"abc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn assert_provider_error(response: CryptoOperationResponse, reason: CryptoErrorReason) {
    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Provider(error)) = error.error else {
        panic!("operation error did not contain the provider branch");
    };
    assert_eq!(error.reason.as_known(), Some(reason));
}
