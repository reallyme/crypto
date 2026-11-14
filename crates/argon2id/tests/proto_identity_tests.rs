// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-derived identity parity, rejected modifiers and stable metadata bytes.

#![cfg(feature = "proto")]
#![allow(missing_docs)]

use buffa::{Enumeration, Message};
use crypto_argon2id::{Argon2KdfVersion, Argon2Profile};
use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2idKdfVersion, CryptoArgon2idProfileIdentifier,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn argon2_profile_parity_covers_every_generated_identity_and_exact_wire_bytes() {
    for &value in Argon2idKdfVersion::values() {
        let identifier = CryptoArgon2idProfileIdentifier {
            kdf_version: value.into(),
        };
        let expected: Option<(Argon2Profile, &[u8])> = match value {
            Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1 => Some((Argon2Profile::V1, &[0x08, 0x01])),
            Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2 => Some((Argon2Profile::V2, &[0x08, 0x02])),
            _ => None,
        };
        match expected {
            Some((native, wire)) => {
                assert_eq!(Argon2Profile::try_from(&identifier), Ok(native));
                let reverse = CryptoArgon2idProfileIdentifier::from(native);
                assert_eq!(reverse.kdf_version.as_known(), Some(value));
                assert_eq!(reverse.encode_to_vec().as_slice(), wire);
            }
            None => {
                assert_eq!(
                    value.to_i32(),
                    0,
                    "every registered identity needs an explicit native mapping"
                );
                assert_eq!(
                    Argon2Profile::try_from(&identifier),
                    Err(UnsupportedProtoAlgorithm)
                );
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn argon2_profile_rejects_zero_negative_and_unknown_numbers() {
    for number in [i32::MIN, -1, 0, 99_999, i32::MAX] {
        let identifier = CryptoArgon2idProfileIdentifier {
            kdf_version: number.into(),
        };
        assert_eq!(
            Argon2Profile::try_from(&identifier),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn argon2_profile_rejects_unknown_wire_modifiers() {
    let identifier = CryptoArgon2idProfileIdentifier::from(Argon2Profile::V1);
    let mut bytes = identifier.encode_to_vec();
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    assert_eq!(
        crypto_proto::wire::decode_protobuf::<CryptoArgon2idProfileIdentifier>(&bytes),
        Err(crypto_proto::wire::CryptoWireError::malformed_protobuf())
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn argon2_kdf_version_parity_covers_every_generated_identity_and_exact_wire_bytes() {
    for &value in Argon2idKdfVersion::values() {
        let identifier = CryptoArgon2idProfileIdentifier {
            kdf_version: value.into(),
        };
        let expected: Option<(Argon2KdfVersion, &[u8])> = match value {
            Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1 => {
                Some((Argon2KdfVersion::V1, &[0x08, 0x01]))
            }
            Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2 => {
                Some((Argon2KdfVersion::V2, &[0x08, 0x02]))
            }
            _ => None,
        };
        match expected {
            Some((native, wire)) => {
                assert_eq!(Argon2KdfVersion::try_from(&identifier), Ok(native));
                let reverse = CryptoArgon2idProfileIdentifier::from(native);
                assert_eq!(reverse.kdf_version.as_known(), Some(value));
                assert_eq!(reverse.encode_to_vec().as_slice(), wire);
            }
            None => {
                assert_eq!(
                    value.to_i32(),
                    0,
                    "every registered identity needs an explicit native mapping"
                );
                assert_eq!(
                    Argon2KdfVersion::try_from(&identifier),
                    Err(UnsupportedProtoAlgorithm)
                );
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn argon2_kdf_version_rejects_zero_negative_and_unknown_numbers() {
    for number in [i32::MIN, -1, 0, 99_999, i32::MAX] {
        let identifier = CryptoArgon2idProfileIdentifier {
            kdf_version: number.into(),
        };
        assert_eq!(
            Argon2KdfVersion::try_from(&identifier),
            Err(UnsupportedProtoAlgorithm)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn argon2_kdf_version_rejects_unknown_wire_modifiers() {
    let identifier = CryptoArgon2idProfileIdentifier::from(Argon2KdfVersion::V1);
    let mut bytes = identifier.encode_to_vec();
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    assert_eq!(
        crypto_proto::wire::decode_protobuf::<CryptoArgon2idProfileIdentifier>(&bytes),
        Err(crypto_proto::wire::CryptoWireError::malformed_protobuf())
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn decoded_metadata_owners_clear_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoArgon2idProfileIdentifier>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn existing_numeric_profile_versions_remain_unchanged() {
    assert!(matches!(
        Argon2KdfVersion::try_from(1_u32),
        Ok(Argon2KdfVersion::V1)
    ));
    assert!(matches!(
        Argon2KdfVersion::try_from(2_u32),
        Ok(Argon2KdfVersion::V2)
    ));
    for invalid in [0_u32, 3, u32::MAX] {
        assert!(Argon2KdfVersion::try_from(invalid).is_err());
    }
}
