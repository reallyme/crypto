// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated/native identity parity is independent of execution support.

#![cfg(all(feature = "operation-response", feature = "prime-groups"))]

use buffa::{EnumValue, Enumeration, Message};
use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPrimeGroupIdentifier, PrimeGroup as ProtoGroup,
};
use reallyme_crypto::prime_groups::PrimeGroup;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_generated_identity_has_exact_native_parity() -> Result<(), UnsupportedProtoAlgorithm> {
    for value in ProtoGroup::values() {
        let converted = PrimeGroup::try_from(&identifier((*value).into()));
        if value.to_i32() == 0 {
            assert_eq!(converted, Err(UnsupportedProtoAlgorithm));
        } else {
            assert_eq!(ProtoGroup::from(converted?), *value);
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_rejects_absent_zero_and_unknown_values() -> Result<(), buffa::DecodeError> {
    for encoded in [b"".as_slice(), &[0x08, 0x00]] {
        let value = CryptoPrimeGroupIdentifier::decode_from_slice(encoded)?;
        assert_eq!(PrimeGroup::try_from(&value), Err(UnsupportedProtoAlgorithm));
    }
    for unknown in [i32::MIN, -1, 1, 99, 999_999, i32::MAX] {
        assert_eq!(
            PrimeGroup::try_from(&identifier(unknown.into())),
            Err(UnsupportedProtoAlgorithm)
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_rejects_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let modifiers: &[&[u8]] = &[&[0xa0, 0x06, 0x01], &[0xa2, 0x06, 0x03, 0x01, 0x02, 0x03]];
    for modifier in modifiers {
        let mut value = identifier(ProtoGroup::PRIME_GROUP_NIST_P256.into());
        value.merge_from_slice(modifier)?;
        assert_eq!(PrimeGroup::try_from(&value), Err(UnsupportedProtoAlgorithm));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_has_permanent_wire_known_answers() -> Result<(), buffa::DecodeError> {
    let cases: &[(PrimeGroup, &[u8])] = &[
        (PrimeGroup::NistP256, &[0x08, 0x64]),
        (PrimeGroup::NistP384, &[0x08, 0x6e]),
        (PrimeGroup::NistP521, &[0x08, 0x78]),
        (PrimeGroup::BrainpoolP256r1, &[0x08, 0xc8, 0x01]),
        (PrimeGroup::BrainpoolP320r1, &[0x08, 0xd2, 0x01]),
        (PrimeGroup::BrainpoolP384r1, &[0x08, 0xdc, 0x01]),
        (PrimeGroup::BrainpoolP512r1, &[0x08, 0xe6, 0x01]),
        (PrimeGroup::Rfc5114Dh1024_160, &[0x08, 0xac, 0x02]),
        (PrimeGroup::Rfc5114Dh2048_224, &[0x08, 0xb6, 0x02]),
        (PrimeGroup::Rfc5114Dh2048_256, &[0x08, 0xc0, 0x02]),
        (PrimeGroup::NistP192, &[0x08, 0x82, 0x01]),
        (PrimeGroup::BrainpoolP192r1, &[0x08, 0xf0, 0x01]),
        (PrimeGroup::BrainpoolP224r1, &[0x08, 0xfa, 0x01]),
    ];
    for &(native, encoded) in cases {
        let value = identifier(ProtoGroup::from(native).into());
        assert_eq!(value.encode_to_vec(), encoded);
        let decoded = CryptoPrimeGroupIdentifier::decode_from_slice(encoded)?;
        assert_eq!(PrimeGroup::try_from(&decoded), Ok(native));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_clears_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoPrimeGroupIdentifier>();
}

fn identifier(group: EnumValue<ProtoGroup>) -> CryptoPrimeGroupIdentifier {
    CryptoPrimeGroupIdentifier {
        group,
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(not(any(feature = "native", feature = "wasm")))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn group_identity_needs_no_rust_backend_feature() -> Result<(), UnsupportedProtoAlgorithm> {
    for value in ProtoGroup::values() {
        if value.to_i32() != 0 {
            let native = PrimeGroup::try_from(&identifier((*value).into()))?;
            assert_eq!(ProtoGroup::from(native), *value);
        }
    }
    Ok(())
}
