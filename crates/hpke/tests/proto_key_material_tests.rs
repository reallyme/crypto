// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![allow(clippy::field_reassign_with_default)] // Populate existing clearing DTOs.
#![cfg(all(feature = "proto", feature = "backend-native"))]

use buffa::{Message, MessageField};
use crypto_hpke::{proto_key_material, HpkeError, HpkeSuite};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm, CryptoAlgorithmIdentifier,
    CryptoHpkeDeriveKeyPairRequest, CryptoHpkeExactWidthDeriveKeyPairRequest,
    CryptoHpkePublicKeyDescriptor, HpkeSuiteIdentifier,
};
use zeroize::ZeroizeOnDrop;

fn algorithm(suite: HpkeSuite) -> CryptoAlgorithmIdentifier {
    CryptoAlgorithmIdentifier {
        algorithm: Some(Algorithm::HpkeSuite(Box::new(
            HpkeSuiteIdentifier::try_from(suite).unwrap(),
        ))),
    }
}
fn flexible(suite: HpkeSuite, bytes: &[u8]) -> CryptoHpkeDeriveKeyPairRequest {
    let mut request = CryptoHpkeDeriveKeyPairRequest::default();
    request.algorithm = MessageField::some(algorithm(suite));
    assert!(request.input_key_material.extend_from_slice(bytes).is_ok());
    request
}
fn exact(suite: HpkeSuite, bytes: &[u8]) -> CryptoHpkeExactWidthDeriveKeyPairRequest {
    let mut request = CryptoHpkeExactWidthDeriveKeyPairRequest::default();
    request.suite = MessageField::some(HpkeSuiteIdentifier::try_from(suite).unwrap());
    assert!(request.input_key_material.extend_from_slice(bytes).is_ok());
    request
}

#[cfg(all(
    feature = "kem-dh-p384",
    feature = "kdf-hkdf-sha384",
    feature = "aead-aes256-gcm"
))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn flexible_ikm_and_exact_width_contracts_preserve_distinct_native_admission(
) -> Result<(), HpkeError> {
    let suite = crypto_hpke::HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM;
    for length in [0, 31, 32, 48, 49, 64] {
        let mut ikm = zeroize::Zeroizing::new(vec![0x42; length]);
        if let Some(first) = ikm.first_mut() {
            *first = 0;
        }
        let flexible_request = flexible(suite, &ikm);
        match crypto_hpke::derive_keypair_from_ikm(suite, &ikm) {
            Ok(expected) => {
                let (owner, public) =
                    proto_key_material::derive_keypair_from_ikm(&flexible_request)?;
                assert_eq!(owner.public_key, expected.public_key);
                assert_eq!(owner.private_key(), expected.private_key());
                assert_eq!(public.public_key, owner.public_key);
                assert_eq!(
                    HpkeSuite::try_from(public.suite.as_option().unwrap())?,
                    suite
                );
            }
            Err(expected) => assert!(
                matches!(proto_key_material::derive_keypair_from_ikm(&flexible_request),Err(e)if e==expected)
            ),
        }
        let exact_request = exact(suite, &ikm);
        match crypto_hpke::derive_keypair(suite, &ikm) {
            Ok(expected) => {
                let (owner, public) = proto_key_material::derive_keypair_exact(&exact_request)?;
                assert_eq!(owner.public_key, expected.public_key);
                assert_eq!(owner.private_key(), expected.private_key());
                assert_eq!(public.public_key, owner.public_key);
            }
            Err(expected) => assert!(
                matches!(proto_key_material::derive_keypair_exact(&exact_request),Err(e)if e==expected)
            ),
        }
        assert_eq!(flexible_request.input_key_material, ikm.as_slice());
        assert_eq!(exact_request.input_key_material, ikm.as_slice());
        if length == 32 {
            assert!(proto_key_material::derive_keypair_from_ikm(&flexible_request).is_ok());
            assert!(
                matches!(proto_key_material::derive_keypair_exact(&exact_request),Err(e)if e==HpkeError::PRIMITIVE_INVALID_LENGTH)
            );
        }
    }
    Ok(())
}

#[cfg(all(
    feature = "kem-dh-p256",
    feature = "kdf-hkdf-sha256",
    feature = "aead-aes128-gcm"
))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn both_derivation_adapters_match_existing_rfc_recipient_key() -> Result<(), HpkeError> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/base_p256.json")).unwrap();
    let ikm = zeroize::Zeroizing::new(hex::decode(fixture["ikmR"].as_str().unwrap()).unwrap());
    let suite = crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM;
    let (owner, public) = proto_key_material::derive_keypair_exact(&exact(suite, &ikm))?;
    assert_eq!(
        public.public_key,
        hex::decode(fixture["pkRm"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        owner.private_key(),
        hex::decode(fixture["skRm"].as_str().unwrap()).unwrap()
    );
    let (flexible_owner, flexible_public) =
        proto_key_material::derive_keypair_from_ikm(&flexible(suite, &ikm))?;
    assert_eq!(flexible_public.public_key, public.public_key);
    assert_eq!(flexible_owner.private_key(), owner.private_key());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn key_material_requests_reject_unknown_missing_and_zero_suite_without_backend_fallback() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoHpkeDeriveKeyPairRequest>();
    clearing::<CryptoHpkeExactWidthDeriveKeyPairRequest>();
    clearing::<CryptoHpkePublicKeyDescriptor>();
    clearing::<crypto_hpke::HpkePrivateKeyBytes>();
    let unavailable = HpkeSuite::new(
        crypto_hpke::HpkeKemId::DhKemCp256HkdfSha256,
        crypto_hpke::HpkeKdfId::HkdfSha256,
        crypto_hpke::HpkeAeadId::Aes128Gcm,
    );
    let expected = crypto_hpke::derive_keypair_from_ikm(unavailable, &[1; 32])
        .err()
        .unwrap();
    assert_eq!(expected, HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
    assert!(
        matches!(proto_key_material::derive_keypair_from_ikm(&flexible(unavailable,&[1;32])),Err(e)if e==expected)
    );
    let expected = crypto_hpke::derive_keypair(unavailable, &[1; 32])
        .err()
        .unwrap();
    assert!(
        matches!(proto_key_material::derive_keypair_exact(&exact(unavailable,&[1;32])),Err(e)if e==expected)
    );
    assert!(
        matches!(proto_key_material::derive_keypair_exact(&CryptoHpkeExactWidthDeriveKeyPairRequest::default()),Err(e)if e==HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    assert!(
        matches!(proto_key_material::derive_keypair_from_ikm(&CryptoHpkeDeriveKeyPairRequest::default()),Err(e)if e==HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    for value in [0, -1, i32::MAX] {
        let request = CryptoHpkeExactWidthDeriveKeyPairRequest {
            suite: MessageField::some(HpkeSuiteIdentifier {
                kem: value.into(),
                kdf: 1.into(),
                aead: 1.into(),
            }),
            input_key_material: vec![1; 32].into(),
        };
        assert!(
            matches!(proto_key_material::derive_keypair_exact(&request),Err(e)if e==HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let modified =
        CryptoHpkeExactWidthDeriveKeyPairRequest::decode_from_slice(&[0xf8, 7, 1]).unwrap();
    assert!(
        matches!(proto_key_material::derive_keypair_exact(&modified),Err(e)if e==HpkeError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut request = CryptoHpkeExactWidthDeriveKeyPairRequest::default();
    assert!(request
        .input_key_material
        .extend_from_slice(&[1; 32])
        .is_ok());
    buffa::Message::clear(&mut request);
    assert!(
        request.input_key_material.is_empty() || request.input_key_material.iter().all(|b| *b == 0)
    );
}
