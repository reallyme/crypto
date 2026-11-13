// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registry identity parity is separate from executable provider support.

#![cfg(feature = "hpke-identities")]
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto_proto::convert::UnsupportedProtoAlgorithm;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
};

#[test]
fn every_registered_generated_component_combination_round_trips() {
    for kem in HpkeKemId::values() {
        for kdf in HpkeKdfId::values() {
            for aead in HpkeAeadId::values() {
                let value = HpkeSuiteIdentifier {
                    kem: (*kem).into(),
                    kdf: (*kdf).into(),
                    aead: (*aead).into(),
                    __buffa_unknown_fields: Default::default(),
                };
                let converted = crypto_hpke::HpkeSuite::try_from(&value);
                if kem.to_i32() == 0 || kdf.to_i32() == 0 || aead.to_i32() == 0 {
                    assert_eq!(converted, Err(UnsupportedProtoAlgorithm));
                } else {
                    let native = converted
                        .expect("registered identity converts without selecting a backend");
                    assert_eq!(i32::from(native.kem_id()), kem.to_i32());
                    assert_eq!(i32::from(native.kdf_id()), kdf.to_i32());
                    assert_eq!(i32::from(native.aead_id()), aead.to_i32());
                    assert_eq!(HpkeSuiteIdentifier::try_from(native), Ok(value));
                }
            }
        }
    }
}

#[test]
fn unknown_negative_and_out_of_range_components_are_rejected() {
    for unknown in [i32::MIN, -1, 65_536, i32::MAX] {
        let mut kem = base_profile();
        kem.kem = EnumValue::from(unknown);
        let mut kdf = base_profile();
        kdf.kdf = EnumValue::from(unknown);
        let mut aead = base_profile();
        aead.aead = EnumValue::from(unknown);
        for invalid in [kem, kdf, aead] {
            assert_eq!(
                crypto_hpke::HpkeSuite::try_from(&invalid),
                Err(UnsupportedProtoAlgorithm)
            );
        }
    }
}

#[test]
fn unknown_suite_fields_do_not_become_ignored_policy() -> Result<(), buffa::DecodeError> {
    let mut suite = base_profile();
    suite.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        crypto_hpke::HpkeSuite::try_from(&suite),
        Err(UnsupportedProtoAlgorithm)
    );
    Ok(())
}

#[test]
fn base_p256_profile_is_the_existing_exact_registry_triple() {
    assert_eq!(
        crypto_hpke::HpkeSuite::try_from(&base_profile()),
        Ok(crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM),
    );
}

fn base_profile() -> HpkeSuiteIdentifier {
    HpkeSuiteIdentifier {
        kem: HpkeKemId::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256.into(),
        kdf: HpkeKdfId::HPKE_KDF_ID_HKDF_SHA256.into(),
        aead: HpkeAeadId::HPKE_AEAD_ID_AES_128_GCM.into(),
        __buffa_unknown_fields: Default::default(),
    }
}
