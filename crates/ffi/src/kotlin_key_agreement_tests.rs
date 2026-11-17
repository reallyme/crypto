// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::algorithm;
use buffa::Enumeration;
use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::KeyAgreementAlgorithm;

#[test]
fn key_agreement_selectors_use_schema_identity_and_reject_other_lanes() {
    for (selector, expected) in [
        (
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH,
            Algorithm::P256,
        ),
        (
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P384_ECDH,
            Algorithm::P384,
        ),
        (
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P521_ECDH,
            Algorithm::P521,
        ),
    ] {
        assert_eq!(algorithm(selector.to_i32()), Ok(expected));
    }
    for selector in [
        0,
        -1,
        i32::MAX,
        KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.to_i32(),
    ] {
        assert_eq!(
            algorithm(selector),
            Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
}
