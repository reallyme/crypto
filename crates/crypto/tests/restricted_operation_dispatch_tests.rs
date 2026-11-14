// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binary request acceptance and rejection under the Ed25519-only profile.

#![cfg(all(
    feature = "operation-response",
    feature = "native",
    feature = "ed25519",
    not(any(
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305"
    ))
))]

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity,
    __buffa::oneof::crypto_error::Error as ErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation,
    __buffa::oneof::crypto_operation_response::Outcome,
    __buffa::oneof::crypto_operation_result::Result as OperationResult, AeadAlgorithm,
    CryptoAeadOpenRequest, CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoOperationRequest,
    CryptoOperationResponse, CryptoSignatureSignRequest, KeyAgreementAlgorithm, SignatureAlgorithm,
};
use reallyme_crypto::operation_contract::process_operation_response_output;

#[test]
fn unknown_operation_wire_tag_is_rejected_before_dispatch() {
    // Field 9 is unassigned in the operation oneof. Its complete empty
    // submessage is well-formed wire data with an unsupported field number.
    let response = process_operation_response_output(&[0x4a, 0x00]);
    assert_error(
        &response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF,
    );
}

#[test]
fn restricted_binary_requests_respect_operation_and_identifier_gates() {
    let unsupported = CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM;
    let request = CryptoAeadOpenRequest::default()
        .with_algorithm(identifier(Identity::Aead(AeadAlgorithm::Aes256Gcm.into())));
    let disabled = execute(Operation::AeadOpen(Box::new(request)));
    assert_error(&disabled, unsupported);

    for algorithm in [
        EnumValue::from(SignatureAlgorithm::EcdsaP256Sha256),
        EnumValue::from(SignatureAlgorithm::Unspecified),
        EnumValue::from(i32::MAX),
    ] {
        assert_error(&sign(Identity::Signature(algorithm)), unsupported);
    }
    assert_error(
        &sign(Identity::KeyAgreement(KeyAgreementAlgorithm::X25519.into())),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER,
    );
    assert!(matches!(
        sign(Identity::Signature(SignatureAlgorithm::Ed25519.into())).outcome.as_ref(),
        Some(Outcome::Result(result))
            if matches!(result.result.as_ref(), Some(OperationResult::SignatureSign(value)) if value.signature.len() == 64)
    ));
}

fn sign(algorithm: Identity) -> CryptoOperationResponse {
    execute(Operation::SignatureSign(Box::new(
        CryptoSignatureSignRequest {
            algorithm: identifier(algorithm),
            message: b"provider selection".to_vec().into(),
            secret_key: vec![7; 32].into(),
        },
    )))
}

fn identifier(
    algorithm: Identity,
) -> MessageField<CryptoAlgorithmIdentifier, buffa::Inline<CryptoAlgorithmIdentifier>> {
    MessageField::some(CryptoAlgorithmIdentifier {
        algorithm: Some(algorithm),
    })
}

fn execute(operation: Operation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
    };
    let bytes = zeroize::Zeroizing::new(request.encode_to_vec());
    process_operation_response_output(&bytes)
}

fn assert_error(response: &CryptoOperationResponse, reason: CryptoErrorReason) {
    let error = match response.outcome.as_ref() {
        Some(Outcome::Error(error)) => error.error.as_ref(),
        _ => None,
    };
    let observed = match error {
        Some(ErrorBranch::Provider(error))
            if reason == CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM =>
        {
            error.reason.as_known()
        }
        Some(ErrorBranch::Primitive(error))
            if reason != CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM =>
        {
            error.reason.as_known()
        }
        _ => None,
    };
    assert_eq!(observed, Some(reason));
}
