// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "aes",
    feature = "chacha20-poly1305",
    feature = "operation-response"
))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Generated operation-response coverage for AEAD semantics.

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch, AeadAlgorithm,
    CryptoAeadOpenRequest, CryptoAeadSealRequest, CryptoAlgorithmIdentifier, CryptoErrorReason,
    CryptoOperationRequest, CryptoOperationResponse,
};
use crypto_proto::operation_response_wire::decode_operation_response;
use crypto_proto::wire::MAX_CRYPTO_PROTO_MESSAGE_BYTES;

#[test]
fn operation_response_aead_seal_uses_operation_owner_for_aes256_gcm() {
    let key = bytes(32, 0x10);
    let nonce = bytes(12, 0x20);
    let aad = b"generated AEAD aad".to_vec();
    let plaintext = b"generated AEAD plaintext".to_vec();
    let response = process_response(aead_seal_request(
        AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        key.clone(),
        nonce.clone(),
        aad.clone(),
        plaintext.clone(),
    ));

    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::AeadSeal(result)) = result.result else {
        panic!("operation result did not contain the AEAD seal branch");
    };

    assert_eq!(
        result.ciphertext_with_tag,
        reallyme_crypto::operations::aead::seal(
            reallyme_crypto::AeadAlgorithm::Aes256Gcm,
            &key,
            &nonce,
            &aad,
            &plaintext,
        )
        .expect("AEAD operation seal succeeds")
    );
}

#[test]
fn operation_response_aead_open_uses_operation_owner_for_xchacha20_poly1305() {
    let key = bytes(32, 0x30);
    let nonce = bytes(24, 0x40);
    let aad = b"AEAD xchacha aad".to_vec();
    let plaintext = b"AEAD xchacha plaintext".to_vec();
    let ciphertext_with_tag = reallyme_crypto::operations::aead::seal(
        reallyme_crypto::AeadAlgorithm::XChaCha20Poly1305,
        &key,
        &nonce,
        &aad,
        &plaintext,
    )
    .expect("AEAD operation seal succeeds");
    let response = process_response(aead_open_request(
        AeadAlgorithm::AEAD_ALGORITHM_XCHACHA20_POLY1305,
        key,
        nonce,
        aad,
        ciphertext_with_tag,
    ));

    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a generated result");
    };
    let Some(CryptoOperationResultBranch::AeadOpen(result)) = result.result else {
        panic!("operation result did not contain the AEAD open branch");
    };

    assert_eq!(result.plaintext, plaintext);
}

#[test]
fn operation_response_aead_open_reports_tampering_as_primitive_authentication_error() {
    let key = bytes(32, 0x50);
    let nonce = bytes(12, 0x60);
    let aad = b"aad".to_vec();
    let mut ciphertext_with_tag = reallyme_crypto::operations::aead::seal(
        reallyme_crypto::AeadAlgorithm::Aes256Gcm,
        &key,
        &nonce,
        &aad,
        b"plaintext",
    )
    .expect("AEAD operation seal succeeds");
    let first = ciphertext_with_tag
        .first_mut()
        .expect("ciphertext with tag is not empty");
    *first ^= 0x01;

    let response = process_response(aead_open_request(
        AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        key,
        nonce,
        aad,
        ciphertext_with_tag,
    ));

    assert_error_response(
        response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_AUTHENTICATION_FAILED,
    );
}

#[test]
fn operation_response_aead_seal_reports_invalid_key_as_primitive_error() {
    let response = process_response(aead_seal_request(
        AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        vec![0x10; 31],
        bytes(12, 0x20),
        b"aad".to_vec(),
        b"plaintext".to_vec(),
    ));

    assert_error_response(
        response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_KEY,
    );
}

#[test]
fn operation_response_aead_unspecified_algorithm_is_provider_error() {
    let response = process_response(aead_seal_request(
        AeadAlgorithm::AEAD_ALGORITHM_UNSPECIFIED,
        bytes(32, 0x10),
        bytes(12, 0x20),
        b"aad".to_vec(),
        b"plaintext".to_vec(),
    ));

    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Provider(error)) = error.error else {
        panic!("operation error did not contain the provider branch");
    };
    assert_eq!(
        error.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[test]
fn operation_response_aead_rejects_oversized_plaintext_before_dispatch() {
    let response = process_response(aead_seal_request(
        AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        bytes(32, 0x10),
        bytes(12, 0x20),
        Vec::new(),
        vec![0_u8; MAX_CRYPTO_PROTO_MESSAGE_BYTES],
    ));

    assert_error_response(
        response,
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
    );
}

fn process_response(request: CryptoOperationRequest) -> CryptoOperationResponse {
    let output = reallyme_crypto::operation_contract::process_operation_response(
        request.encode_to_vec().as_slice(),
    );
    decode_operation_response(output.as_slice()).expect("response decodes")
}

fn aead_seal_request(
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
) -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::AeadSeal(Box::new(CryptoAeadSealRequest {
            algorithm: MessageField::some(aead_identifier(algorithm)),
            key,
            nonce,
            aad,
            plaintext,
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn aead_open_request(
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    ciphertext_with_tag: Vec<u8>,
) -> CryptoOperationRequest {
    CryptoOperationRequest {
        operation: Some(CryptoOperation::AeadOpen(Box::new(CryptoAeadOpenRequest {
            algorithm: MessageField::some(aead_identifier(algorithm)),
            key,
            nonce,
            aad,
            ciphertext_with_tag,
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn aead_identifier(algorithm: AeadAlgorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Aead(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn assert_error_response(response: CryptoOperationResponse, reason: CryptoErrorReason) {
    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Primitive(error)) = error.error else {
        panic!("operation error did not contain the primitive branch");
    };
    assert_eq!(error.reason.as_known(), Some(reason));
}

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(u8::try_from(index).expect("test vector length fits in u8")))
        .collect()
}
