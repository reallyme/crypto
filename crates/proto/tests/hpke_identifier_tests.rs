// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HPKE identifier and generated wire-contract tests.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier, HpkeAeadId,
    HpkeKdfId, HpkeKemId, HpkeSuiteIdentifier,
};

#[test]
fn hpke_registry_identifier_values_are_stable() {
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256.to_i32(),
        0x0010
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_P384_HKDF_SHA384.to_i32(),
        0x0011
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_P521_HKDF_SHA512.to_i32(),
        0x0012
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_CP256_HKDF_SHA256.to_i32(),
        0x0013
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_CP384_HKDF_SHA384.to_i32(),
        0x0014
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_CP521_HKDF_SHA512.to_i32(),
        0x0015
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_SECP256K1_HKDF_SHA256.to_i32(),
        0x0016
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256.to_i32(),
        0x0020
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_X448_HKDF_SHA512.to_i32(),
        0x0021
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_DHKEM_X25519_ELLIGATOR_HKDF_SHA256.to_i32(),
        0x0022
    );
    assert_eq!(
        HpkeKemId::HPKE_KEM_ID_X25519_KYBER768_DRAFT00.to_i32(),
        0x0030
    );
    assert_eq!(HpkeKemId::HPKE_KEM_ID_ML_KEM_512.to_i32(), 0x0040);
    assert_eq!(HpkeKemId::HPKE_KEM_ID_ML_KEM_768.to_i32(), 0x0041);
    assert_eq!(HpkeKemId::HPKE_KEM_ID_ML_KEM_1024.to_i32(), 0x0042);
    assert_eq!(HpkeKemId::HPKE_KEM_ID_ML_KEM_768_P256.to_i32(), 0x0050);
    assert_eq!(HpkeKemId::HPKE_KEM_ID_ML_KEM_1024_P384.to_i32(), 0x0051);
    assert_eq!(HpkeKemId::HPKE_KEM_ID_X_WING.to_i32(), 0x647a);

    assert_eq!(HpkeKdfId::HPKE_KDF_ID_HKDF_SHA256.to_i32(), 0x0001);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_HKDF_SHA384.to_i32(), 0x0002);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_HKDF_SHA512.to_i32(), 0x0003);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_SHAKE128.to_i32(), 0x0010);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_SHAKE256.to_i32(), 0x0011);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_TURBO_SHAKE128.to_i32(), 0x0012);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_TURBO_SHAKE256.to_i32(), 0x0013);

    assert_eq!(HpkeAeadId::HPKE_AEAD_ID_AES_128_GCM.to_i32(), 0x0001);
    assert_eq!(HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM.to_i32(), 0x0002);
    assert_eq!(HpkeAeadId::HPKE_AEAD_ID_CHACHA20_POLY1305.to_i32(), 0x0003);
    assert_eq!(HpkeAeadId::HPKE_AEAD_ID_EXPORT_ONLY.to_i32(), 0xffff);
}

#[test]
fn hpke_suite_identifier_wire_contract_is_stable() -> Result<(), buffa::DecodeError> {
    let identifier = CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::HpkeSuite(Box::new(HpkeSuiteIdentifier {
            kem: EnumValue::from(HpkeKemId::HPKE_KEM_ID_ML_KEM_1024),
            kdf: EnumValue::from(HpkeKdfId::HPKE_KDF_ID_SHAKE256),
            aead: EnumValue::from(HpkeAeadId::HPKE_AEAD_ID_AES_256_GCM),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let expected = [0x5a, 0x06, 0x08, 0x42, 0x10, 0x11, 0x18, 0x02];

    assert_eq!(identifier.encode_to_vec(), expected);
    let mut bytes = expected.as_slice();
    assert_eq!(CryptoAlgorithmIdentifier::decode(&mut bytes)?, identifier);

    Ok(())
}

#[test]
fn unspecified_hpke_components_remain_explicit_sentinels() {
    assert_eq!(HpkeKemId::HPKE_KEM_ID_UNSPECIFIED.to_i32(), 0);
    assert_eq!(HpkeKdfId::HPKE_KDF_ID_UNSPECIFIED.to_i32(), 0);
    assert_eq!(HpkeAeadId::HPKE_AEAD_ID_UNSPECIFIED.to_i32(), 0);
}
