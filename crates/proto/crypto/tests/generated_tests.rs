// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Tests for generated protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    SignatureAlgorithm,
};

#[test]
fn signature_algorithm_enum_value_is_stable() {
    assert_eq!(SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519.to_i32(), 1);
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
