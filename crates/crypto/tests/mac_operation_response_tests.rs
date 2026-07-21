// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "operation-response")]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Generated operation-response coverage for MAC semantics.

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoMacAuthenticateRequest,
    CryptoMacVerifyRequest, CryptoOperationRequest, CryptoOperationResponse,
    CryptoVerificationStatus, MacAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;

#[test]
fn operation_response_mac_authenticate_uses_operation_owner_for_sha512() {
    let key = vec![0x42u8; 32];
    let message = b"reallyme operation-response MAC".to_vec();
    let output = reallyme_crypto::operation_contract::process_operation_response(
        mac_authenticate_request(
            MacAlgorithm::MAC_ALGORITHM_HMAC_SHA512,
            key.clone(),
            message.clone(),
        )
        .encode_to_vec()
        .as_slice(),
    );
    let response = decode_operation_response(output.as_slice()).expect("response decodes");

    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::MacAuthenticate(mac)) = result.result else {
        panic!("operation result did not contain the MAC authenticate branch");
    };

    assert_eq!(
        mac.tag,
        reallyme_crypto::operations::mac::authenticate(
            reallyme_crypto::MacAlgorithm::HmacSha512,
            &key,
            &message,
        )
        .expect("operation MAC succeeds")
    );
}

#[test]
fn operation_response_mac_verify_reports_mismatch_as_invalid_result() {
    let key = vec![0x24u8; 32];
    let message = b"message".to_vec();
    let mut tag = reallyme_crypto::operations::mac::authenticate(
        reallyme_crypto::MacAlgorithm::HmacSha256,
        &key,
        &message,
    )
    .expect("operation MAC succeeds");
    let first = tag.first_mut().expect("tag is not empty");
    *first ^= 0x01;

    let response = mac_verify_response(MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256, key, message, tag);
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::MacVerify(verification)) = result.result else {
        panic!("operation result did not contain the MAC verify branch");
    };

    assert_eq!(
        verification.status.as_known(),
        Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_INVALID)
    );
    assert!(verification.error.as_option().is_none());
}

#[test]
fn operation_response_mac_verify_reports_malformed_tag_as_error_result() {
    let response = mac_verify_response(
        MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256,
        vec![0x24u8; 32],
        b"message".to_vec(),
        vec![0u8; 31],
    );
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::MacVerify(verification)) = result.result else {
        panic!("operation result did not contain the MAC verify branch");
    };

    assert_eq!(
        verification.status.as_known(),
        Some(CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_ERROR)
    );
    let error = verification
        .error
        .as_option()
        .expect("malformed tag returns a verification error");
    let Some(CryptoErrorBranch::Primitive(error)) = error.error.as_ref() else {
        panic!("verification error did not contain the primitive branch");
    };
    assert_eq!(
        error.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_LENGTH)
    );
}

#[test]
fn operation_response_mac_unspecified_algorithm_is_provider_error() {
    let output = reallyme_crypto::operation_contract::process_operation_response(
        mac_authenticate_request(
            MacAlgorithm::MAC_ALGORITHM_UNSPECIFIED,
            vec![0x42u8; 32],
            b"message".to_vec(),
        )
        .encode_to_vec()
        .as_slice(),
    );
    let response = decode_operation_response(output.as_slice()).expect("response decodes");

    assert_provider_error(
        response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

fn mac_verify_response(
    algorithm: MacAlgorithm,
    key: Vec<u8>,
    message: Vec<u8>,
    tag: Vec<u8>,
) -> CryptoOperationResponse {
    let output = reallyme_crypto::operation_contract::process_operation_response(
        mac_verify_request(algorithm, key, message, tag)
            .encode_to_vec()
            .as_slice(),
    );
    decode_operation_response(output.as_slice()).expect("response decodes")
}

fn mac_authenticate_request(
    algorithm: MacAlgorithm,
    key: Vec<u8>,
    message: Vec<u8>,
) -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::MacAuthenticate(Box::new(
            CryptoMacAuthenticateRequest {
                algorithm: MessageField::some(mac_identifier(algorithm)),
                key,
                message,
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn mac_verify_request(
    algorithm: MacAlgorithm,
    key: Vec<u8>,
    message: Vec<u8>,
    tag: Vec<u8>,
) -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::MacVerify(Box::new(
            CryptoMacVerifyRequest {
                algorithm: MessageField::some(mac_identifier(algorithm)),
                key,
                message,
                tag,
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn mac_identifier(algorithm: MacAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Mac(EnumValue::from(algorithm))),
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
