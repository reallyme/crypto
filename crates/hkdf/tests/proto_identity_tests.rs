// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-derived identity parity, rejected modifiers and stable metadata bytes.

#![cfg(feature = "proto")]
#![allow(missing_docs)]

use buffa::{Enumeration, Message};
use crypto_hkdf::HkdfSuite;
use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfSuiteIdentifier, HashAlgorithm,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hkdf_suite_parity_covers_every_generated_identity_and_exact_wire_bytes() {
    for &value in HashAlgorithm::values() {
        let identifier = CryptoHkdfSuiteIdentifier { hash: value.into() };
        let expected: Option<(HkdfSuite, &[u8])> = match value {
            HashAlgorithm::HASH_ALGORITHM_SHA2_256 => Some((HkdfSuite::Sha2_256, &[0x08, 0x64])),
            HashAlgorithm::HASH_ALGORITHM_SHA2_384 => Some((HkdfSuite::Sha2_384, &[0x08, 0x6e])),
            HashAlgorithm::HASH_ALGORITHM_SHA3_256 => {
                Some((HkdfSuite::Sha3_256, &[0x08, 0xd2, 0x01]))
            }
            _ => None,
        };
        match expected {
            Some((native, wire)) => {
                assert_eq!(HkdfSuite::try_from(&identifier), Ok(native));
                let reverse = CryptoHkdfSuiteIdentifier::from(native);
                assert_eq!(reverse.hash.as_known(), Some(value));
                assert_eq!(reverse.encode_to_vec().as_slice(), wire);
            }
            None => {
                assert_eq!(
                    HkdfSuite::try_from(&identifier),
                    Err(UnsupportedProtoAlgorithm)
                );
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hkdf_suite_rejects_zero_negative_and_unknown_numbers() {
    for number in [i32::MIN, -1, 0, 99_999, i32::MAX] {
        let identifier = CryptoHkdfSuiteIdentifier {
            hash: number.into(),
        };
        assert_eq!(
            HkdfSuite::try_from(&identifier),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hkdf_suite_rejects_unknown_wire_modifiers() {
    let identifier = CryptoHkdfSuiteIdentifier::from(HkdfSuite::Sha2_256);
    let mut bytes = identifier.encode_to_vec();
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    assert_eq!(
        crypto_proto::wire::decode_protobuf::<CryptoHkdfSuiteIdentifier>(&bytes),
        Err(crypto_proto::wire::CryptoWireError::malformed_protobuf())
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn decoded_metadata_owners_clear_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoHkdfSuiteIdentifier>();
}

#[cfg(not(feature = "sha3"))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn sha3_identity_does_not_require_the_optional_sha3_implementation() {
    let identifier = CryptoHkdfSuiteIdentifier::from(HkdfSuite::Sha3_256);
    assert_eq!(HkdfSuite::try_from(&identifier), Ok(HkdfSuite::Sha3_256));
    assert_eq!(
        identifier.hash.as_known(),
        Some(HashAlgorithm::HASH_ALGORITHM_SHA3_256)
    );
}
