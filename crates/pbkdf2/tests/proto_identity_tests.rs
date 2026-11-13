// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-derived identity parity, rejected modifiers and stable metadata bytes.

#![cfg(feature = "proto")]
#![allow(missing_docs)]

use buffa::{Enumeration, Message};
use crypto_pbkdf2::Pbkdf2Prf;
use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPbkdf2PrfIdentifier, MacAlgorithm,
};

#[test]
fn pbkdf2_prf_parity_covers_every_generated_identity_and_exact_wire_bytes() {
    for &value in MacAlgorithm::values() {
        let identifier = CryptoPbkdf2PrfIdentifier {
            prf: value.into(),
            __buffa_unknown_fields: Default::default(),
        };
        let expected: Option<(Pbkdf2Prf, &[u8])> = match value {
            MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256 => Some((Pbkdf2Prf::HmacSha256, &[0x08, 0x64])),
            MacAlgorithm::MAC_ALGORITHM_HMAC_SHA512 => Some((Pbkdf2Prf::HmacSha512, &[0x08, 0x78])),
            _ => None,
        };
        match expected {
            Some((native, wire)) => {
                assert_eq!(Pbkdf2Prf::try_from(&identifier), Ok(native));
                let reverse = CryptoPbkdf2PrfIdentifier::from(native);
                assert_eq!(reverse.prf.as_known(), Some(value));
                assert!(reverse.__buffa_unknown_fields.is_empty());
                assert_eq!(reverse.encode_to_vec().as_slice(), wire);
            }
            None => {
                assert_eq!(
                    Pbkdf2Prf::try_from(&identifier),
                    Err(UnsupportedProtoAlgorithm)
                );
            }
        }
    }
}

#[test]
fn pbkdf2_prf_rejects_zero_negative_and_unknown_numbers() {
    for number in [i32::MIN, -1, 0, 99_999, i32::MAX] {
        let identifier = CryptoPbkdf2PrfIdentifier {
            prf: number.into(),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(
            Pbkdf2Prf::try_from(&identifier),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[test]
fn pbkdf2_prf_rejects_retained_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let mut identifier = CryptoPbkdf2PrfIdentifier::from(Pbkdf2Prf::HmacSha256);
    // Unknown field 100 is public test data, not an accepted policy modifier.
    identifier.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert!(!identifier.__buffa_unknown_fields.is_empty());
    assert_eq!(
        Pbkdf2Prf::try_from(&identifier),
        Err(UnsupportedProtoAlgorithm)
    );
    Ok(())
}

#[test]
fn decoded_metadata_owners_clear_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoPbkdf2PrfIdentifier>();
}
