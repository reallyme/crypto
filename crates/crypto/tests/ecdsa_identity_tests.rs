// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated/native identity parity is independent of execution support.

#![cfg(all(feature = "operation-response", feature = "ecdsa-explicit"))]

use buffa::{EnumValue, Enumeration, Message};
use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity, AeadAlgorithm,
    CryptoAlgorithmIdentifier, HashAlgorithm, SignatureAlgorithm,
};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoEcdsaCurveIdentifier, EcdsaCurve as ProtoCurve,
};
use reallyme_crypto::ecdsa_explicit::{EcdsaCurve, EcdsaHash};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_generated_identity_has_exact_native_parity() -> Result<(), UnsupportedProtoAlgorithm> {
    for value in ProtoCurve::values() {
        let converted = EcdsaCurve::try_from(&identifier((*value).into()));
        if value.to_i32() == 0 {
            assert_eq!(converted, Err(UnsupportedProtoAlgorithm));
        } else {
            assert_eq!(ProtoCurve::from(converted?), *value);
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_rejects_absent_zero_and_unknown_values() -> Result<(), buffa::DecodeError> {
    for encoded in [b"".as_slice(), &[0x08, 0x00]] {
        let value = CryptoEcdsaCurveIdentifier::decode_from_slice(encoded)?;
        assert_eq!(EcdsaCurve::try_from(&value), Err(UnsupportedProtoAlgorithm));
    }
    for unknown in [i32::MIN, -1, 1, 99, 999_999, i32::MAX] {
        assert_eq!(
            EcdsaCurve::try_from(&identifier(unknown.into())),
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
        let mut value = identifier(ProtoCurve::ECDSA_CURVE_NIST_P256.into());
        value.merge_from_slice(modifier)?;
        assert_eq!(EcdsaCurve::try_from(&value), Err(UnsupportedProtoAlgorithm));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_has_permanent_wire_known_answers() -> Result<(), buffa::DecodeError> {
    let cases: &[(EcdsaCurve, &[u8])] = &[
        (EcdsaCurve::P256, &[0x08, 0x64]),
        (EcdsaCurve::P384, &[0x08, 0x6e]),
        (EcdsaCurve::P521, &[0x08, 0x78]),
        (EcdsaCurve::BrainpoolP256r1, &[0x08, 0xc8, 0x01]),
        (EcdsaCurve::BrainpoolP320r1, &[0x08, 0xd2, 0x01]),
        (EcdsaCurve::BrainpoolP384r1, &[0x08, 0xdc, 0x01]),
        (EcdsaCurve::BrainpoolP512r1, &[0x08, 0xe6, 0x01]),
    ];
    for &(native, encoded) in cases {
        let value = identifier(ProtoCurve::from(native).into());
        assert_eq!(value.encode_to_vec(), encoded);
        let decoded = CryptoEcdsaCurveIdentifier::decode_from_slice(encoded)?;
        assert_eq!(EcdsaCurve::try_from(&decoded), Ok(native));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_clears_retained_unknown_storage_on_drop() {
    fn require_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    require_cleanup::<CryptoEcdsaCurveIdentifier>();
}

fn identifier(curve: EnumValue<ProtoCurve>) -> CryptoEcdsaCurveIdentifier {
    CryptoEcdsaCurveIdentifier {
        curve,
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg(not(any(feature = "brainpool", feature = "brainpool-openssl")))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn brainpool_identity_is_available_when_its_provider_is_disabled() {
    for curve in [
        EcdsaCurve::BrainpoolP256r1,
        EcdsaCurve::BrainpoolP320r1,
        EcdsaCurve::BrainpoolP384r1,
        EcdsaCurve::BrainpoolP512r1,
    ] {
        let value = identifier(ProtoCurve::from(curve).into());
        assert_eq!(EcdsaCurve::try_from(&value), Ok(curve));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_generated_hash_is_the_exact_sha2_subset_or_rejected() {
    for value in HashAlgorithm::values() {
        let expected = match value {
            HashAlgorithm::HASH_ALGORITHM_SHA2_256 => Ok(EcdsaHash::Sha256),
            HashAlgorithm::HASH_ALGORITHM_SHA2_384 => Ok(EcdsaHash::Sha384),
            HashAlgorithm::HASH_ALGORITHM_SHA2_512 => Ok(EcdsaHash::Sha512),
            _ => Err(UnsupportedProtoAlgorithm),
        };
        assert_eq!(
            EcdsaHash::try_from(&hash_identifier((*value).into())),
            expected
        );
        if let Ok(native) = expected {
            assert_eq!(HashAlgorithm::from(native), *value);
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hash_metadata_rejects_missing_unknown_and_wrong_family() {
    assert_eq!(
        EcdsaHash::try_from(&CryptoAlgorithmIdentifier::default()),
        Err(UnsupportedProtoAlgorithm)
    );
    for unknown in [i32::MIN, -1, 0, 999_999, i32::MAX] {
        assert_eq!(
            EcdsaHash::try_from(&hash_identifier(unknown.into())),
            Err(UnsupportedProtoAlgorithm)
        );
    }
    for wrong in [
        Identity::Aead(AeadAlgorithm::AEAD_ALGORITHM_AES_128_GCM.into()),
        Identity::Signature(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256.into()),
    ] {
        let value = CryptoAlgorithmIdentifier {
            algorithm: Some(wrong),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(EcdsaHash::try_from(&value), Err(UnsupportedProtoAlgorithm));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hash_metadata_rejects_unknown_modifiers() -> Result<(), buffa::DecodeError> {
    let modifiers: &[&[u8]] = &[&[0xa0, 0x06, 0x01], &[0xa2, 0x06, 0x03, 0x01, 0x02, 0x03]];
    for modifier in modifiers {
        let mut value = hash_identifier(HashAlgorithm::HASH_ALGORITHM_SHA2_256.into());
        value.merge_from_slice(modifier)?;
        assert_eq!(EcdsaHash::try_from(&value), Err(UnsupportedProtoAlgorithm));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ecdsa_hashes_keep_existing_schema_wire_tags() -> Result<(), buffa::DecodeError> {
    let cases: &[(EcdsaHash, &[u8])] = &[
        (EcdsaHash::Sha256, &[0x30, 0x64]),
        (EcdsaHash::Sha384, &[0x30, 0x6e]),
        (EcdsaHash::Sha512, &[0x30, 0x78]),
    ];
    for &(native, encoded) in cases {
        let value = hash_identifier(HashAlgorithm::from(native).into());
        assert_eq!(value.encode_to_vec(), encoded);
        let decoded = CryptoAlgorithmIdentifier::decode_from_slice(encoded)?;
        assert_eq!(EcdsaHash::try_from(&decoded), Ok(native));
    }
    Ok(())
}

fn hash_identifier(hash: EnumValue<HashAlgorithm>) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(Identity::Hash(hash)),
        __buffa_unknown_fields: Default::default(),
    }
}
