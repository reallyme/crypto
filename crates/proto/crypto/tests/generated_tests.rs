// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for generated protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto_proto::generated::{
    proto::reallyme::crypto::v1::{
        __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
        CryptoError, CryptoErrorReason, CryptoPrimitiveError, SignatureAlgorithm,
    },
    CRYPTO_PROTO_PACKAGE,
};

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
fn crypto_error_envelope_round_trips_with_buffa() {
    let error = CryptoError {
        error: CryptoPrimitiveError {
            reason: EnumValue::from(
                CryptoErrorReason::CRYPTO_ERROR_REASON_PRIMITIVE_VERIFICATION_FAILED,
            ),
            __buffa_unknown_fields: Default::default(),
        }
        .into(),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = error.encode_to_vec();
    let decoded = CryptoError::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, error);
}

#[test]
fn algorithm_identifier_round_trips_with_buffa() {
    let identifier = CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::Signature(EnumValue::from(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519,
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let encoded = identifier.encode_to_vec();
    let decoded = CryptoAlgorithmIdentifier::decode(&mut encoded.as_slice()).unwrap();

    assert_eq!(decoded, identifier);
}
