// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "concat-kdf",
    feature = "hkdf",
    feature = "kmac",
    feature = "argon2id",
    feature = "pbkdf2",
    feature = "operation-response"
))]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

//! Generated operation-response coverage for every exposed KDF branch.

use buffa::{EnumValue, Message, MessageField};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as ProtoAlgorithmBranch,
    __buffa::oneof::crypto_error::Error as CryptoErrorBranch,
    __buffa::oneof::crypto_operation_request::Operation as CryptoOperation,
    __buffa::oneof::crypto_operation_response::Outcome as CryptoOperationOutcome,
    __buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch,
    Argon2idKdfVersion, CryptoAlgorithmIdentifier, CryptoArgon2idDeriveRequest, CryptoErrorReason,
    CryptoHkdfDeriveRequest, CryptoJwaConcatKdfSha256DeriveRequest, CryptoKdfDeriveKeyRequest,
    CryptoKmac256DeriveRequest, CryptoOperationRequest, CryptoOperationResponse,
    KdfAlgorithm as ProtoKdf,
};
use crypto_proto::operation_response_wire::decode_operation_response;

#[test]
fn operation_response_exposes_every_kdf_result_branch() {
    assert_result_branch(
        CryptoOperation::Argon2idDerive(Box::new(CryptoArgon2idDeriveRequest {
            algorithm: MessageField::some(kdf_identifier(ProtoKdf::KDF_ALGORITHM_ARGON2ID)),
            kdf_version: EnumValue::from(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1),
            secret: b"KDF password".to_vec(),
            salt: b"KDF Argon2 salt!".to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| matches!(branch, CryptoOperationResultBranch::Argon2idDerive(result) if result.derived_key.len() == 32),
    );

    assert_result_branch(
        CryptoOperation::HkdfDerive(Box::new(CryptoHkdfDeriveRequest {
            algorithm: MessageField::some(kdf_identifier(ProtoKdf::KDF_ALGORITHM_HKDF_SHA384)),
            input_key_material: b"KDF shared secret".to_vec(),
            salt: b"KDF salt".to_vec(),
            info: b"KDF info".to_vec(),
            output_length: 32,
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| matches!(branch, CryptoOperationResultBranch::HkdfDerive(result) if result.output_key_material.len() == 32),
    );

    assert_result_branch(
        CryptoOperation::KdfDeriveKey(Box::new(CryptoKdfDeriveKeyRequest {
            algorithm: MessageField::some(kdf_identifier(
                ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA256,
            )),
            password: b"KDF password".to_vec(),
            salt: b"KDF salt".to_vec(),
            iterations: reallyme_crypto::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS,
            output_length: 32,
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| matches!(branch, CryptoOperationResultBranch::KdfDeriveKey(result) if result.derived_key.len() == 32),
    );

    assert_result_branch(
        CryptoOperation::JwaConcatKdfSha256Derive(Box::new(
            CryptoJwaConcatKdfSha256DeriveRequest {
                algorithm: MessageField::some(kdf_identifier(
                    ProtoKdf::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256,
                )),
                shared_secret: b"KDF ECDH secret".to_vec(),
                algorithm_id: b"A256GCM".to_vec(),
                party_u_info: b"party u".to_vec(),
                party_v_info: b"party v".to_vec(),
                output_length: 32,
                __buffa_unknown_fields: Default::default(),
            },
        )),
        |branch| matches!(branch, CryptoOperationResultBranch::JwaConcatKdfSha256Derive(result) if result.derived_key.len() == 32),
    );

    assert_result_branch(
        CryptoOperation::Kmac256Derive(Box::new(CryptoKmac256DeriveRequest {
            algorithm: MessageField::some(kdf_identifier(ProtoKdf::KDF_ALGORITHM_KMAC_256)),
            key: vec![0x42; 32],
            context: b"KDF context".to_vec(),
            customization: b"KDF customization".to_vec(),
            output_length: 32,
            __buffa_unknown_fields: Default::default(),
        })),
        |branch| matches!(branch, CryptoOperationResultBranch::Kmac256Derive(result) if result.derived_key.len() == 32),
    );
}

#[test]
fn operation_response_rejects_unspecified_argon2id_profile_before_derivation() {
    let response = process_response(CryptoOperation::Argon2idDerive(Box::new(
        CryptoArgon2idDeriveRequest {
            algorithm: MessageField::some(kdf_identifier(ProtoKdf::KDF_ALGORITHM_ARGON2ID)),
            kdf_version: EnumValue::from(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_UNSPECIFIED),
            secret: b"KDF password".to_vec(),
            salt: b"KDF Argon2 salt!".to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )));

    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Primitive(error)) = error.error else {
        panic!("operation error did not contain the primitive branch");
    };
    assert_eq!(
        error.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER)
    );
}

#[test]
fn operation_response_preserves_typed_modern_policy_failure() {
    let response = process_response(CryptoOperation::KdfDeriveKey(Box::new(
        CryptoKdfDeriveKeyRequest {
            algorithm: MessageField::some(kdf_identifier(
                ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA512,
            )),
            password: b"KDF password".to_vec(),
            salt: b"KDF salt".to_vec(),
            iterations: reallyme_crypto::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS - 1,
            output_length: 32,
            __buffa_unknown_fields: Default::default(),
        },
    )));

    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Primitive(error)) = error.error else {
        panic!("operation error did not contain the primitive branch");
    };
    assert_eq!(
        error.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER)
    );
}

#[test]
fn operation_response_rejects_excessive_pbkdf2_work_before_derivation() {
    let response = process_response(CryptoOperation::KdfDeriveKey(Box::new(
        CryptoKdfDeriveKeyRequest {
            algorithm: MessageField::some(kdf_identifier(
                ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA512,
            )),
            password: b"KDF password".to_vec(),
            salt: b"KDF salt".to_vec(),
            iterations: u32::MAX,
            output_length: 32,
            __buffa_unknown_fields: Default::default(),
        },
    )));

    let Some(CryptoOperationOutcome::Error(error)) = response.outcome else {
        panic!("operation response did not contain an error");
    };
    let Some(CryptoErrorBranch::Primitive(error)) = error.error else {
        panic!("operation error did not contain the primitive branch");
    };
    assert_eq!(
        error.reason.as_known(),
        Some(CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER)
    );
}

fn assert_result_branch(
    operation: CryptoOperation,
    assertion: impl FnOnce(&CryptoOperationResultBranch) -> bool,
) {
    let response = process_response(operation);
    let Some(CryptoOperationOutcome::Result(result)) = response.outcome else {
        panic!("operation response did not contain a result");
    };
    let Some(branch) = result.result.as_ref() else {
        panic!("operation result did not contain a branch");
    };
    assert!(assertion(branch));
}

fn process_response(operation: CryptoOperation) -> CryptoOperationResponse {
    let request = CryptoOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let output = reallyme_crypto::operation_contract::process_operation_response(
        request.encode_to_vec().as_slice(),
    );
    decode_operation_response(output.as_slice()).expect("response decodes")
}

fn kdf_identifier(algorithm: ProtoKdf) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(ProtoAlgorithmBranch::Kdf(EnumValue::from(algorithm))),
        __buffa_unknown_fields: Default::default(),
    }
}
