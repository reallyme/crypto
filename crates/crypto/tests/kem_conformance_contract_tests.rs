// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs, clippy::unwrap_used)]
#![cfg(all(feature = "operation-response", feature = "test-vectors"))]

use buffa::{Enumeration, Message, MessageField};
#[cfg(all(
    feature = "dispatch",
    any(feature = "native", feature = "wasm"),
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
use crypto_core::Algorithm;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity, CryptoAlgorithmIdentifier,
    CryptoKemConformanceEncapsulateRequest, CryptoKemEncapsulation, KemAlgorithm,
};
use reallyme_crypto::conformance_contract;
use zeroize::ZeroizeOnDrop;

fn request(
    algorithm: KemAlgorithm,
    public: &[u8],
    randomness: &[u8],
) -> CryptoKemConformanceEncapsulateRequest {
    let mut request = CryptoKemConformanceEncapsulateRequest {
        algorithm: MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Identity::Kem(algorithm.into())),
            __buffa_unknown_fields: Default::default(),
        }),
        public_key: Vec::new(),
        encapsulation_randomness: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    request.public_key.extend_from_slice(public);
    request
        .encapsulation_randomness
        .extend_from_slice(randomness);
    request
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_kem_identity_missing_unknown_selector_and_owner_cleanup_are_explicit() {
    fn clearing<T: ZeroizeOnDrop>() {
        assert!(core::mem::needs_drop::<T>());
    }
    clearing::<CryptoKemConformanceEncapsulateRequest>();
    clearing::<CryptoKemEncapsulation>();
    assert_eq!(
        request(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512, &[0, 255], &[1, 0]).encode_to_vec(),
        [10, 3, 24, 0xe8, 7, 18, 2, 0, 255, 26, 2, 1, 0]
    );
    assert!(
        matches!(conformance_contract::encapsulate(&CryptoKemConformanceEncapsulateRequest::default()),Err(e)if e==CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    for value in KemAlgorithm::values() {
        let probe = request(*value, &[], &[]);
        assert!(conformance_contract::encapsulate(&probe).is_err());
    }
    for value in [0, -1, 1, 999, i32::MAX] {
        let mut probe = request(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512, &[], &[]);
        probe.algorithm = MessageField::some(CryptoAlgorithmIdentifier {
            algorithm: Some(Identity::Kem(value.into())),
            __buffa_unknown_fields: Default::default(),
        });
        assert!(
            matches!(conformance_contract::encapsulate(&probe),Err(e)if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
        );
    }
    let mut wrong_family = request(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512, &[], &[]);
    wrong_family.algorithm=MessageField::some(CryptoAlgorithmIdentifier{algorithm:Some(Identity::Hash(crypto_proto::generated::proto::reallyme::crypto::v1::HashAlgorithm::HASH_ALGORITHM_SHA2_256.into())),__buffa_unknown_fields:Default::default()});
    assert!(
        matches!(conformance_contract::encapsulate(&wrong_family),Err(error)if error==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut probe = request(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512, &[], &[1; 32]);
    let mut bytes = probe.encode_to_vec();
    bytes.extend_from_slice(&[0xf8, 7, 1]);
    let modified = CryptoKemConformanceEncapsulateRequest::decode_from_slice(&bytes).unwrap();
    assert!(
        matches!(conformance_contract::encapsulate(&modified),Err(e)if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    let mut nested_bytes = probe.algorithm.as_option().unwrap().encode_to_vec();
    nested_bytes.extend_from_slice(&[0xf8, 7, 1]);
    let nested = CryptoAlgorithmIdentifier::decode_from_slice(&nested_bytes).unwrap();
    probe.algorithm = MessageField::some(nested);
    assert!(
        matches!(conformance_contract::encapsulate(&probe),Err(e)if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    );
    buffa::Message::clear(&mut probe);
    assert!(
        probe.encapsulation_randomness.is_empty()
            || probe.encapsulation_randomness.iter().all(|b| *b == 0)
    );
}

#[cfg(all(
    feature = "dispatch",
    any(feature = "native", feature = "wasm"),
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_selected_kems_preserve_exact_coins_ciphertext_secret_and_native_errors(
) -> Result<(), CryptoError> {
    let cases: [(Algorithm, KemAlgorithm, usize, usize); 4] = [
        (
            Algorithm::MlKem512,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_512,
            64,
            32,
        ),
        (
            Algorithm::MlKem768,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768,
            64,
            32,
        ),
        (
            Algorithm::MlKem1024,
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024,
            64,
            32,
        ),
        (
            Algorithm::XWing768,
            KemAlgorithm::KEM_ALGORITHM_X_WING_768,
            32,
            64,
        ),
    ];
    for (native, wire, seed_len, coins_len) in cases {
        let key = match reallyme_crypto::operations::kem::derive_key_pair(
            native,
            &vec![7; seed_len],
        ) {
            Ok(key) => key,
            Err(e) if e == CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM => {
                assert!(
                    matches!(conformance_contract::encapsulate(&request(wire,&[],&[])),Err(e)if e==CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
                );
                continue;
            }
            Err(e) => return Err(e),
        };
        let coins = zeroize::Zeroizing::new(vec![0x5a; coins_len]);
        let probe = request(wire, &key.public_key, &coins);
        let expected =
            reallyme_crypto::operations::kem::encapsulate_derand(native, &key.public_key, &coins)?;
        let actual = conformance_contract::encapsulate(&probe)?;
        assert_eq!(actual.ciphertext, expected.ciphertext);
        assert_eq!(actual.shared_secret, expected.shared_secret.as_slice());
        let repeated = conformance_contract::encapsulate(&probe)?;
        assert_eq!(actual.ciphertext, repeated.ciphertext);
        assert_eq!(actual.shared_secret, repeated.shared_secret);
        assert_eq!(
            reallyme_crypto::operations::kem::decapsulate(
                native,
                &actual.ciphertext,
                &key.secret_key
            )?
            .as_slice(),
            actual.shared_secret
        );
        let mut changed = request(wire, &key.public_key, &coins);
        changed.encapsulation_randomness[0] ^= 1;
        assert_ne!(
            conformance_contract::encapsulate(&changed)?.ciphertext,
            actual.ciphertext
        );
        for bad in [Vec::new(), vec![1; coins_len - 1], vec![1; coins_len + 1]] {
            let expected =
                reallyme_crypto::operations::kem::encapsulate_derand(native, &key.public_key, &bad)
                    .err()
                    .unwrap();
            assert!(
                matches!(conformance_contract::encapsulate(&request(wire,&key.public_key,&bad)),Err(e)if e==expected)
            );
        }
        let expected = reallyme_crypto::operations::kem::encapsulate_derand(native, &[], &coins)
            .err()
            .unwrap();
        assert!(
            matches!(conformance_contract::encapsulate(&request(wire,&[],&coins)),Err(e)if e==expected)
        );
    }
    Ok(())
}
