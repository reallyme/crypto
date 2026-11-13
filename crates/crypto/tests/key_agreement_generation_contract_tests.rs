// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(feature = "operation-response")]

use buffa::{EnumValue, Enumeration, Message, MessageField};
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Branch, CryptoAlgorithmIdentifier,
    CryptoKeyAgreementGenerateKeyPairRequest, CryptoKeyPair, KeyAgreementAlgorithm,
    SignatureAlgorithm,
};
use reallyme_crypto::key_agreement_contract::generate_key_pair;

fn request(value: EnumValue<KeyAgreementAlgorithm>) -> CryptoKeyAgreementGenerateKeyPairRequest {
    CryptoKeyAgreementGenerateKeyPairRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Branch::KeyAgreement(value)),
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn missing_wrong_family_unknown_identities_and_modifiers_fail_closed() {
    assert_eq!(
        generate_key_pair(&CryptoKeyAgreementGenerateKeyPairRequest::default()).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut wrong = request(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.into());
    wrong.algorithm = MessageField::some(CryptoAlgorithmIdentifier {
        algorithm: Some(Branch::Signature(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519.into(),
        )),
        __buffa_unknown_fields: Default::default(),
    });
    assert_eq!(
        generate_key_pair(&wrong).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    let mut absent = request(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.into());
    absent.algorithm = MessageField::some(CryptoAlgorithmIdentifier::default());
    assert_eq!(
        generate_key_pair(&absent).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for value in [0, -1, 1, 999_999, i32::MAX] {
        assert_eq!(
            generate_key_pair(&request(EnumValue::from(value))).err(),
            Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut nested = CryptoAlgorithmIdentifier {
        algorithm: Some(Branch::KeyAgreement(
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.into(),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    nested.merge_from_slice(&[0xa2, 6, 3, 0, 255, 1]).unwrap();
    let mut modified = request(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.into());
    modified.algorithm = MessageField::some(nested);
    assert_eq!(
        generate_key_pair(&modified).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut outer = request(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.into());
    outer.merge_from_slice(&[0xa2, 6, 3, 0, 255, 1]).unwrap();
    assert_eq!(
        generate_key_pair(&outer).err(),
        Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_generated_key_agreement_identities_have_exact_feature_behavior() -> Result<(), CryptoError> {
    for value in KeyAgreementAlgorithm::values() {
        if *value == KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED {
            continue;
        }
        let probe = request((*value).into());
        // Each case has its own feature gate. An all-feature build folds these
        // predicates to true, but a matches! rewrite would lose sparse lanes.
        #[allow(clippy::match_like_matches_macro)]
        let enabled = match value {
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519 => cfg!(all(
                feature = "dispatch",
                feature = "x25519",
                any(
                    feature = "native",
                    all(feature = "wasm", target_arch = "wasm32")
                )
            )),
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH => cfg!(all(
                feature = "dispatch",
                feature = "p256",
                any(
                    feature = "native",
                    all(feature = "wasm", target_arch = "wasm32")
                )
            )),
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P384_ECDH => cfg!(all(
                feature = "dispatch",
                feature = "p384",
                any(
                    feature = "native",
                    all(feature = "wasm", target_arch = "wasm32")
                )
            )),
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P521_ECDH => cfg!(all(
                feature = "dispatch",
                feature = "p521",
                any(
                    feature = "native",
                    all(feature = "wasm", target_arch = "wasm32")
                )
            )),
            _ => false,
        };
        if !enabled {
            assert_eq!(
                generate_key_pair(&probe).err(),
                Some(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
            );
            continue;
        }
        #[cfg(all(
            feature = "dispatch",
            any(feature = "native", all(feature = "wasm", target_arch = "wasm32")),
            any(
                feature = "x25519",
                feature = "p256",
                feature = "p384",
                feature = "p521"
            )
        ))]
        {
            let mut generated = generate_key_pair(&probe)?;
            let native = crypto_core::Algorithm::try_from(probe.algorithm.as_option().unwrap())
                .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
            let reconstructed = reallyme_crypto::operations::key_agreement::derive_key_pair(
                native,
                &generated.secret_key,
            )?;
            assert_eq!(generated.public_key, reconstructed.public_key);
            assert_eq!(
                generated.secret_key.as_slice(),
                reconstructed.secret_key.as_slice()
            );
            assert_eq!(
                generated.algorithm.as_option().unwrap().algorithm,
                probe.algorithm.as_option().unwrap().algorithm
            );
            #[cfg(feature = "x25519")]
            if native == crypto_core::Algorithm::X25519 {
                let seed = <&[u8; 32]>::try_from(generated.secret_key.as_slice()).unwrap();
                let (public, secret) = crypto_x25519::generate_x25519_keypair_from_seed(seed);
                assert_eq!(generated.public_key, public);
                assert_eq!(generated.secret_key.as_slice(), secret.as_slice());
            }
            #[cfg(feature = "p256")]
            if native == crypto_core::Algorithm::P256 {
                let scalar = <&[u8; 32]>::try_from(generated.secret_key.as_slice()).unwrap();
                let (public, secret) = crypto_p256::generate_p256_keypair_from_secret_key(scalar)?;
                assert_eq!(generated.public_key, public);
                assert_eq!(generated.secret_key.as_slice(), secret.as_slice());
            }
            #[cfg(feature = "p384")]
            if native == crypto_core::Algorithm::P384 {
                let scalar = <&[u8; 48]>::try_from(generated.secret_key.as_slice()).unwrap();
                let (public, secret) = crypto_p384::generate_p384_keypair_from_secret_key(scalar)?;
                assert_eq!(generated.public_key, public);
                assert_eq!(generated.secret_key.as_slice(), secret.as_slice());
            }
            #[cfg(feature = "p521")]
            if native == crypto_core::Algorithm::P521 {
                let scalar = <&[u8; 66]>::try_from(generated.secret_key.as_slice()).unwrap();
                let (public, secret) = crypto_p521::generate_p521_keypair_from_secret_key(scalar)?;
                assert_eq!(generated.public_key, public);
                assert_eq!(generated.secret_key.as_slice(), secret.as_slice());
            }
            Message::clear(&mut generated);
            assert!(generated.secret_key.is_empty());
            assert!(generated.public_key.is_empty());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn generation_request_and_result_have_clearing_owners_and_exact_wire_identity() {
    fn clearing<T: zeroize::ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoKeyAgreementGenerateKeyPairRequest>();
    clearing::<CryptoKeyPair>();
    let probe = request(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519.into());
    assert_eq!(probe.encode_to_vec(), [10, 2, 16, 100]);
}
