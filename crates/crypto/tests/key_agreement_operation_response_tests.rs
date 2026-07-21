// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated operation-response coverage for every key-agreement raw-key branch.

#![cfg(all(
    feature = "operation-response",
    feature = "x25519",
    feature = "p256",
    feature = "p384",
    feature = "p521"
))]
#![allow(clippy::expect_used)]

use buffa::{EnumValue, Message, MessageField};
use crypto_core::Algorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    CryptoAlgorithmIdentifier, CryptoErrorReason, CryptoKeyAgreementDeriveKeyPairRequest,
    CryptoKeyAgreementDeriveSharedSecretRequest, CryptoOperationRequest, CryptoOperationResponse,
    KeyAgreementAlgorithm,
};
use crypto_proto::operation_response_wire::decode_operation_response;

struct AgreementCase {
    algorithm: Algorithm,
    proto_algorithm: KeyAgreementAlgorithm,
    secret_key: Vec<u8>,
    peer_secret_key: Vec<u8>,
    public_key_len: usize,
    shared_secret_len: usize,
}

#[test]
fn operation_response_exposes_every_key_agreement_result_branch() {
    for case in agreement_cases() {
        let first = reallyme_crypto::operations::key_agreement::derive_key_pair(
            case.algorithm,
            &case.secret_key,
        )
        .expect("valid key-agreement scalar derives a keypair");
        let second = reallyme_crypto::operations::key_agreement::derive_key_pair(
            case.algorithm,
            &case.peer_secret_key,
        )
        .expect("valid key-agreement peer scalar derives a keypair");
        let expected_shared_secret =
            reallyme_crypto::operations::key_agreement::derive_shared_secret(
                case.algorithm,
                &case.secret_key,
                &second.public_key,
            )
            .expect("valid key agreement succeeds");

        let derived = result_branch(CryptoOperation::KeyAgreementDeriveKeyPair(Box::new(
            CryptoKeyAgreementDeriveKeyPairRequest {
                algorithm: MessageField::some(key_agreement_identifier(case.proto_algorithm)),
                secret_key: case.secret_key.clone(),
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("derive-keypair returns a generated result branch");
        assert!(matches!(
            derived,
            CryptoOperationResultBranch::KeyAgreementDeriveKeyPair(ref key_pair)
                if key_pair.public_key == first.public_key
                    && key_pair.secret_key == case.secret_key
                    && key_pair.public_key.len() == case.public_key_len
                    && result_algorithm(&key_pair.algorithm) == Some(case.proto_algorithm)
        ));

        let shared = result_branch(CryptoOperation::KeyAgreementDeriveSharedSecret(Box::new(
            CryptoKeyAgreementDeriveSharedSecretRequest {
                algorithm: MessageField::some(key_agreement_identifier(case.proto_algorithm)),
                public_key: second.public_key,
                secret_key: case.secret_key,
                __buffa_unknown_fields: Default::default(),
            },
        )))
        .expect("shared-secret derivation returns a generated result branch");
        assert!(matches!(
            shared,
            CryptoOperationResultBranch::KeyAgreementDeriveSharedSecret(ref result)
                if result.shared_secret == *expected_shared_secret
                    && result.shared_secret.len() == case.shared_secret_len
                    && result_algorithm(&result.algorithm) == Some(case.proto_algorithm)
        ));
    }
}

#[test]
fn operation_response_returns_typed_errors_for_every_key_agreement_invalid_key_path() {
    for case in agreement_cases() {
        let peer = reallyme_crypto::operations::key_agreement::derive_key_pair(
            case.algorithm,
            &case.peer_secret_key,
        )
        .expect("valid key-agreement peer scalar derives a keypair");
        assert_error_reason(
            CryptoOperation::KeyAgreementDeriveKeyPair(Box::new(
                CryptoKeyAgreementDeriveKeyPairRequest {
                    algorithm: MessageField::some(key_agreement_identifier(case.proto_algorithm)),
                    secret_key: vec![1, 2],
                    __buffa_unknown_fields: Default::default(),
                },
            )),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );
        assert_error_reason(
            CryptoOperation::KeyAgreementDeriveSharedSecret(Box::new(
                CryptoKeyAgreementDeriveSharedSecretRequest {
                    algorithm: MessageField::some(key_agreement_identifier(case.proto_algorithm)),
                    public_key: vec![3, 4],
                    secret_key: case.secret_key.clone(),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );
        assert_error_reason(
            CryptoOperation::KeyAgreementDeriveSharedSecret(Box::new(
                CryptoKeyAgreementDeriveSharedSecretRequest {
                    algorithm: MessageField::some(key_agreement_identifier(case.proto_algorithm)),
                    public_key: peer.public_key,
                    secret_key: vec![1, 2],
                    __buffa_unknown_fields: Default::default(),
                },
            )),
            CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
        );
    }
}

#[test]
fn operation_response_fails_closed_for_unknown_key_agreement_routes() {
    assert_error_reason(
        CryptoOperation::KeyAgreementDeriveKeyPair(Box::new(
            CryptoKeyAgreementDeriveKeyPairRequest {
                algorithm: MessageField::some(key_agreement_identifier(
                    KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED,
                )),
                secret_key: vec![9; 32],
                __buffa_unknown_fields: Default::default(),
            },
        )),
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
    );
}

fn agreement_cases() -> [AgreementCase; 4] {
    [
        AgreementCase {
            algorithm: Algorithm::X25519,
            proto_algorithm: KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519,
            secret_key: vec![9; 32],
            peer_secret_key: vec![11; 32],
            public_key_len: 32,
            shared_secret_len: 32,
        },
        AgreementCase {
            algorithm: Algorithm::P256,
            proto_algorithm: KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH,
            secret_key: vec![5; 32],
            peer_secret_key: vec![7; 32],
            public_key_len: 33,
            shared_secret_len: 32,
        },
        AgreementCase {
            algorithm: Algorithm::P384,
            proto_algorithm: KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P384_ECDH,
            secret_key: vec![3; 48],
            peer_secret_key: vec![5; 48],
            public_key_len: 49,
            shared_secret_len: 48,
        },
        AgreementCase {
            algorithm: Algorithm::P521,
            proto_algorithm: KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P521_ECDH,
            secret_key: p521_secret_key(3),
            peer_secret_key: p521_secret_key(5),
            public_key_len: 67,
            shared_secret_len: 66,
        },
    ]
}

fn p521_secret_key(last_byte: u8) -> Vec<u8> {
    let mut secret_key = vec![0; 66];
    secret_key[65] = last_byte;
    secret_key
}

fn result_branch(operation: CryptoOperation) -> Option<CryptoOperationResultBranch> {
    match process_response(operation).outcome {
        Some(CryptoOperationOutcome::Result(result)) => result.result,
        _ => None,
    }
}

fn result_algorithm(
    identifier: &MessageField<
        CryptoAlgorithmIdentifier,
        impl buffa::ProtoBox<CryptoAlgorithmIdentifier>,
    >,
) -> Option<KeyAgreementAlgorithm> {
    match identifier.as_option()?.algorithm.as_ref()? {
        ProtoAlgorithmBranch::KeyAgreement(value) => value.as_known(),
        _ => None,
    }
}

fn assert_error_reason(operation: CryptoOperation, expected: CryptoErrorReason) {
    let response = process_response(operation);
    let reason = match response.outcome {
        Some(CryptoOperationOutcome::Error(error)) => match error.error {
            Some(CryptoErrorBranch::Primitive(error)) => error.reason.as_known(),
            Some(CryptoErrorBranch::Provider(error)) => error.reason.as_known(),
            Some(CryptoErrorBranch::Backend(error)) => error.reason.as_known(),
            None => None,
        },
        _ => None,
    };
    assert_eq!(reason, Some(expected));
}

fn process_response(operation: CryptoOperation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let output = reallyme_crypto::operation_contract::process_operation_response(
        request.encode_to_vec().as_slice(),
    );
    decode_operation_response(output.as_slice()).expect("operation response decodes")
}

fn key_agreement_identifier(algorithm: KeyAgreementAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::KeyAgreement(EnumValue::from(
            algorithm,
        ))),
        __buffa_unknown_fields: Default::default(),
    }
}
