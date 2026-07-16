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
        },
        AeadAlgorithm, CryptoAeadSealRequest, CryptoAlgorithmIdentifier, CryptoBackendError,
        CryptoError, CryptoErrorReason, CryptoKeyPair, CryptoPrimitiveError, CryptoProviderError,
        HashAlgorithm, HpkeSuite, KdfAlgorithm, KemAlgorithm, KeyAgreementAlgorithm,
        KeyWrapAlgorithm, MacAlgorithm, MulticodecKeyAlgorithm, SignatureAlgorithm,
    },
    CRYPTO_PROTO_PACKAGE,
};

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
    assert_eq!(SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519.to_i32(), 1);
}

#[test]
fn proto_package_names_are_stable() {
    assert_eq!(CRYPTO_PROTO_PACKAGE, "reallyme.crypto.v1");
}

#[test]
fn error_reason_enum_values_are_stable() {
    assert_eq!(
        CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED.to_i32(),
        121
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
        &[0x08, 0x01],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::KeyAgreement(EnumValue::from(
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519,
        ))),
        &[0x10, 0x01],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Kem(EnumValue::from(
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768,
        ))),
        &[0x18, 0x02],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Hpke(EnumValue::from(
            HpkeSuite::HPKE_SUITE_DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
        ))),
        &[0x20, 0x02],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Aead(EnumValue::from(
            AeadAlgorithm::AEAD_ALGORITHM_AES_256_GCM,
        ))),
        &[0x28, 0x01],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Hash(EnumValue::from(
            HashAlgorithm::HASH_ALGORITHM_SHA2_256,
        ))),
        &[0x30, 0x01],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Mac(EnumValue::from(
            MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256,
        ))),
        &[0x38, 0x01],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::Kdf(EnumValue::from(
            KdfAlgorithm::KDF_ALGORITHM_HKDF_SHA256,
        ))),
        &[0x40, 0x01],
    )?;
    assert_golden_wire(
        &algorithm_identifier(Algorithm::KeyWrap(EnumValue::from(
            KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW,
        ))),
        &[0x48, 0x01],
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
            0x0a, 0x02, 0x18, 0x02, 0x12, 0x02, 0x01, 0x02, 0x1a, 0x02, 0x03, 0x04,
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
            0x0a, 0x02, 0x28, 0x01, 0x12, 0x01, 0x01, 0x1a, 0x01, 0x02, 0x22, 0x01, 0x03, 0x2a,
            0x01, 0x04,
        ],
    )
}
