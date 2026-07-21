// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for generated protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto_proto::generated::{
    proto::reallyme::crypto::v1::{
        __buffa::oneof::{
            crypto_algorithm_identifier::Algorithm, crypto_error::Error as CryptoErrorBranch,
            crypto_operation_response::Outcome as CryptoOperationOutcome,
            crypto_operation_result::Result as CryptoOperationResultBranch,
        },
        AeadAlgorithm, CryptoAeadSealRequest, CryptoAlgorithmIdentifier, CryptoBackendError,
        CryptoError, CryptoErrorReason, CryptoHashRequest, CryptoKeyPair,
        CryptoKmac256DeriveRequest, CryptoKmac256DeriveRequestOwnedView, CryptoOperationResponse,
        CryptoOperationResponseOwnedView, CryptoOperationResult, CryptoPrimitiveError,
        CryptoProviderError, HashAlgorithm, HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
        KdfAlgorithm, KemAlgorithm, KeyAgreementAlgorithm, KeyWrapAlgorithm, MacAlgorithm,
        MulticodecKeyAlgorithm, SignatureAlgorithm,
    },
    CRYPTO_PROTO_PACKAGE,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
enum GeneratedJsonTestError {
    #[error("failed to serialize generated proto JSON")]
    Serialize,
    #[error("failed to parse generated proto JSON")]
    Parse,
}

fn assert_golden_wire<M>(message: &M, expected: &[u8]) -> Result<(), buffa::DecodeError>
where
    M: Message + Default + PartialEq + core::fmt::Debug,
{
    let encoded = message.encode_to_vec();
    assert_eq!(encoded, expected);

    let mut bytes = expected;
    let decoded = M::decode(&mut bytes)?;
    assert_eq!(&decoded, message);

    Ok(())
}

fn algorithm_identifier(algorithm: Algorithm) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(algorithm),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn signature_algorithm_enum_value_is_stable() {
    assert_eq!(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519.to_i32(),
        100
    );
}

#[test]
fn key_wrap_algorithm_enum_values_follow_logical_key_size_order() {
    // These values are the append-only wire contract.
    assert_eq!(
        KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_128_KW.to_i32(),
        100
    );
    assert_eq!(
        KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_192_KW.to_i32(),
        110
    );
    assert_eq!(
        KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW.to_i32(),
        120
    );
}

#[test]
fn proto_package_names_are_stable() {
    assert_eq!(CRYPTO_PROTO_PACKAGE, "reallyme.crypto.v1");
}

#[test]
fn generated_owned_views_redact_retained_protobuf_buffers() -> Result<(), buffa::DecodeError> {
    let request = CryptoKmac256DeriveRequest {
        algorithm: Default::default(),
        key: vec![251; 32],
        context: vec![252, 253],
        customization: vec![254],
        output_length: 32,
        __buffa_unknown_fields: Default::default(),
    };
    let view = CryptoKmac256DeriveRequestOwnedView::from_owned(&request)?;
    let debug = format!("{view:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("251"));
    assert!(!debug.contains("252"));
    assert!(!debug.contains("253"));
    assert!(!debug.contains("254"));
    Ok(())
}

#[test]
fn generated_sensitive_views_refuse_serde_serialization() -> Result<(), buffa::DecodeError> {
    let request = CryptoKmac256DeriveRequest {
        algorithm: Default::default(),
        key: vec![251; 32],
        context: vec![252, 253],
        customization: vec![254],
        output_length: 32,
        __buffa_unknown_fields: Default::default(),
    };
    let owned_view = CryptoKmac256DeriveRequestOwnedView::from_owned(&request)?;

    assert!(serde_json::to_string(owned_view.view()).is_err());
    assert!(serde_json::to_string(&owned_view).is_err());
    Ok(())
}

#[test]
fn generated_operation_response_owners_redact_nested_secret_material(
) -> Result<(), buffa::DecodeError> {
    let response = CryptoOperationResponse {
        outcome: Some(CryptoOperationOutcome::Result(Box::new(
            CryptoOperationResult {
                result: Some(CryptoOperationResultBranch::SignatureGenerateKeyPair(
                    Box::new(CryptoKeyPair {
                        algorithm: Default::default(),
                        public_key: vec![250],
                        secret_key: vec![251, 252, 253],
                        __buffa_unknown_fields: Default::default(),
                    }),
                )),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let response_debug = format!("{response:?}");
    assert!(response_debug.contains("<redacted>"));
    assert!(!response_debug.contains("250"));
    assert!(!response_debug.contains("251"));
    assert!(!response_debug.contains("252"));
    assert!(!response_debug.contains("253"));

    let owned_view = CryptoOperationResponseOwnedView::from_owned(&response)?;
    let owned_view_debug = format!("{owned_view:?}");
    assert!(owned_view_debug.contains("<redacted>"));
    assert!(!owned_view_debug.contains("250"));
    assert!(!owned_view_debug.contains("251"));
    assert!(!owned_view_debug.contains("252"));
    assert!(!owned_view_debug.contains("253"));
    assert!(serde_json::to_string(owned_view.view()).is_err());
    assert!(serde_json::to_string(&owned_view).is_err());
    Ok(())
}

#[test]
fn error_reason_enum_values_are_stable() {
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED.to_i32(),
        121
    );
}

#[test]
fn platform_key_lifecycle_error_reason_values_are_stable() {
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_KEY_EXISTS.to_i32(),
        204
    );
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_KEY_NOT_FOUND.to_i32(),
        205
    );
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_ACCESS_DENIED.to_i32(),
        206
    );
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_USER_AUTHENTICATION_REQUIRED.to_i32(),
        207
    );
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_USER_CANCELED.to_i32(),
        208
    );
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_UNAVAILABLE.to_i32(),
        209
    );
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_HARDWARE_REJECTED_KEY.to_i32(),
        210
    );
}

#[test]
fn operation_response_codec_rejects_absent_semantic_oneofs() {
    let missing_outcome = CryptoOperationResponse::default();
    let missing_outcome_bytes = missing_outcome.encode_to_vec();
    assert!(
        reallyme_crypto_proto::operation_response_wire::decode_operation_response(
            &missing_outcome_bytes,
        )
        .is_err()
    );
    assert!(
        reallyme_crypto_proto::operation_response_wire::encode_operation_response(
            &missing_outcome,
        )
        .is_err()
    );

    let missing_result = CryptoOperationResponse {
        outcome: Some(CryptoOperationOutcome::Result(
            Box::<CryptoOperationResult>::default(),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    assert!(
        reallyme_crypto_proto::operation_response_wire::decode_operation_response(
            &missing_result.encode_to_vec(),
        )
        .is_err()
    );
    assert!(
        reallyme_crypto_proto::operation_response_wire::encode_operation_response(&missing_result)
            .is_err()
    );

    let malformed_error = CryptoOperationResponse {
        outcome: Some(CryptoOperationOutcome::Error(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };
    assert!(
        reallyme_crypto_proto::operation_response_wire::decode_operation_response(
            &malformed_error.encode_to_vec(),
        )
        .is_err()
    );
    assert!(
        reallyme_crypto_proto::operation_response_wire::encode_operation_response(&malformed_error)
            .is_err()
    );
}

#[test]
fn crypto_error_oneof_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let primitive = CryptoError {
        error: Some(CryptoErrorBranch::Primitive(Box::new(
            CryptoPrimitiveError {
                reason: EnumValue::from(
                    CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE,
                ),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&primitive, &[0x0a, 0x02, 0x08, 0x78])?;

    let provider = CryptoError {
        error: Some(CryptoErrorBranch::Provider(Box::new(CryptoProviderError {
            reason: EnumValue::from(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM,
            ),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&provider, &[0x12, 0x03, 0x08, 0xc8, 0x01])?;

    let backend = CryptoError {
        error: Some(CryptoErrorBranch::Backend(Box::new(CryptoBackendError {
            reason: EnumValue::from(CryptoErrorReason::CRYPTO_ERROR_REASON_BACKEND_INTERNAL),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_golden_wire(&backend, &[0x1a, 0x03, 0x08, 0xad, 0x02])?;

    Ok(())
}

#[test]
fn algorithm_identifier_oneof_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Signature(EnumValue::from(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519,
        ))),
        &[0x08, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::KeyAgreement(EnumValue::from(
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519,
        ))),
        &[0x10, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Kem(EnumValue::from(
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768,
        ))),
        &[0x18, 0xf2, 0x07],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::HpkeSuite(Box::new(HpkeSuiteIdentifier {
            kem: EnumValue::from(HpkeKemId::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256),
            kdf: EnumValue::from(HpkeKdfId::HPKE_KDF_ID_HKDF_SHA256),
            aead: EnumValue::from(HpkeAeadId::HPKE_AEAD_ID_CHACHA20_POLY1305),
            __buffa_unknown_fields: Default::default(),
        }))),
        &[0x5a, 0x06, 0x08, 0x20, 0x10, 0x01, 0x18, 0x03],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Aead(EnumValue::from(
            AeadAlgorithm::AEAD_ALGORITHM_AES_128_GCM,
        ))),
        &[0x28, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Aead(EnumValue::from(
            AeadAlgorithm::AEAD_ALGORITHM_AES_192_GCM,
        ))),
        &[0x28, 0x6e],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Aead(EnumValue::from(
            AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        ))),
        &[0x28, 0x78],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Hash(EnumValue::from(
            HashAlgorithm::HASH_ALGORITHM_SHA2_256,
        ))),
        &[0x30, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Mac(EnumValue::from(
            MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256,
        ))),
        &[0x38, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Mac(EnumValue::from(
            MacAlgorithm::MAC_ALGORITHM_HMAC_SHA384,
        ))),
        &[0x38, 0x6e],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Kdf(EnumValue::from(
            KdfAlgorithm::KDF_ALGORITHM_HKDF_SHA256,
        ))),
        &[0x40, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Kdf(EnumValue::from(
            KdfAlgorithm::KDF_ALGORITHM_HKDF_SHA384,
        ))),
        &[0x40, 0x6e],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Kdf(EnumValue::from(
            KdfAlgorithm::KDF_ALGORITHM_KMAC_256,
        ))),
        &[0x40, 0xf4, 0x03],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::KeyWrap(EnumValue::from(
            KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_128_KW,
        ))),
        &[0x48, 0x64],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::KeyWrap(EnumValue::from(
            KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_192_KW,
        ))),
        &[0x48, 0x6e],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::KeyWrap(EnumValue::from(
            KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW,
        ))),
        &[0x48, 0x78],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::MulticodecKey(EnumValue::from(
            MulticodecKeyAlgorithm::MULTICODEC_KEY_ALGORITHM_ED25519_PUB,
        ))),
        &[0x50, 0x01],
    )?;

    Ok(())
}

#[test]
fn multi_field_crypto_output_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let keypair = CryptoKeyPair {
        algorithm: algorithm_identifier(Algorithm::Kem(EnumValue::from(
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768,
        )))
        .into(),
        public_key: vec![0x01, 0x02],
        secret_key: vec![0x03, 0x04],
        __buffa_unknown_fields: Default::default(),
    };

    assert_golden_wire(
        &keypair,
        &[
            0x0a, 0x03, 0x18, 0xf2, 0x07, 0x12, 0x02, 0x01, 0x02, 0x1a, 0x02, 0x03, 0x04,
        ],
    )
}

#[test]
fn multi_field_crypto_input_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let request = CryptoAeadSealRequest {
        algorithm: algorithm_identifier(Algorithm::Aead(EnumValue::from(
            AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        )))
        .into(),
        key: vec![0x01],
        nonce: vec![0x02],
        aad: vec![0x03],
        plaintext: vec![0x04],
        __buffa_unknown_fields: Default::default(),
    };

    assert_golden_wire(
        &request,
        &[
            0x0a, 0x02, 0x28, 0x78, 0x12, 0x01, 0x01, 0x1a, 0x01, 0x02, 0x22, 0x01, 0x03, 0x2a,
            0x01, 0x04,
        ],
    )
}

#[test]
fn generated_hash_request_supports_strict_proto_json_transport(
) -> Result<(), GeneratedJsonTestError> {
    let request = CryptoHashRequest {
        algorithm: algorithm_identifier(Algorithm::Hash(EnumValue::from(
            HashAlgorithm::HASH_ALGORITHM_SHA2_256,
        )))
        .into(),
        input: b"abc".to_vec(),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded_json =
        serde_json::to_vec(&request).map_err(|_| GeneratedJsonTestError::Serialize)?;
    let json_value: serde_json::Value =
        serde_json::from_slice(&encoded_json).map_err(|_| GeneratedJsonTestError::Parse)?;
    assert_eq!(
        json_value,
        json!({
            "algorithm": {
                "hash": "HASH_ALGORITHM_SHA2_256"
            },
            "input": "YWJj"
        })
    );

    let decoded: CryptoHashRequest =
        serde_json::from_slice(&encoded_json).map_err(|_| GeneratedJsonTestError::Parse)?;
    assert_eq!(decoded, request);
    Ok(())
}

#[test]
fn generated_secret_bearing_request_json_shape_remains_schema_stable(
) -> Result<(), GeneratedJsonTestError> {
    let request = CryptoAeadSealRequest {
        algorithm: algorithm_identifier(Algorithm::Aead(EnumValue::from(
            AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        )))
        .into(),
        key: vec![0x11; 32],
        nonce: vec![0x22; 12],
        aad: b"boundary aad".to_vec(),
        plaintext: b"transport plaintext".to_vec(),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded_json =
        serde_json::to_vec(&request).map_err(|_| GeneratedJsonTestError::Serialize)?;
    let json_value: serde_json::Value =
        serde_json::from_slice(&encoded_json).map_err(|_| GeneratedJsonTestError::Parse)?;
    assert_eq!(
        json_value,
        json!({
            "algorithm": {
                "aead": "AEAD_ALGORITHM_AES_256_GCM"
            },
            "key": "ERERERERERERERERERERERERERERERERERERERERERE=",
            "nonce": "IiIiIiIiIiIiIiIi",
            "aad": "Ym91bmRhcnkgYWFk",
            "plaintext": "dHJhbnNwb3J0IHBsYWludGV4dA=="
        })
    );

    Ok(())
}
