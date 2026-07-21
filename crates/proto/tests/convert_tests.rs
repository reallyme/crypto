// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "generated")]
//! Tests for protobuf-to-core algorithm conversion drift guards.
#![allow(clippy::unwrap_used, clippy::panic)]

use crypto_core::{AeadAlgorithm as CoreAead, Algorithm, HashAlgorithm as CoreHash};
use reallyme_crypto_proto::convert::{
    kem_algorithm_to_proto, key_agreement_algorithm_to_proto, signature_algorithm_to_proto,
};
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::{
    AeadAlgorithm as ProtoAead, HashAlgorithm as ProtoHash, KemAlgorithm, KeyAgreementAlgorithm,
    SignatureAlgorithm,
};

const ALL_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::X25519,
    Algorithm::P256,
    Algorithm::P384,
    Algorithm::P521,
    Algorithm::Secp256k1,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
    Algorithm::SlhDsaSha2_128s,
    Algorithm::MlKem512,
    Algorithm::MlKem768,
    Algorithm::MlKem1024,
    Algorithm::XWing768,
];

#[test]
fn every_algorithm_maps_to_at_least_one_proto_family() {
    for &algorithm in ALL_ALGORITHMS {
        let families = usize::from(signature_algorithm_to_proto(algorithm).is_some())
            + usize::from(key_agreement_algorithm_to_proto(algorithm).is_some())
            + usize::from(kem_algorithm_to_proto(algorithm).is_some());
        assert!(
            families >= 1,
            "{algorithm} has no protobuf identifier in any family"
        );
    }
}

#[test]
fn signature_algorithms_round_trip() {
    for &algorithm in ALL_ALGORITHMS {
        if let Some(proto) = signature_algorithm_to_proto(algorithm) {
            assert_eq!(Algorithm::try_from(proto).unwrap(), algorithm);
        }
    }
}

#[test]
fn key_agreement_algorithms_round_trip() {
    for &algorithm in ALL_ALGORITHMS {
        if let Some(proto) = key_agreement_algorithm_to_proto(algorithm) {
            assert_eq!(Algorithm::try_from(proto).unwrap(), algorithm);
        }
    }
}

#[test]
fn kem_algorithms_round_trip() {
    for &algorithm in ALL_ALGORITHMS {
        if let Some(proto) = kem_algorithm_to_proto(algorithm) {
            assert_eq!(Algorithm::try_from(proto).unwrap(), algorithm);
        }
    }
}

#[test]
fn aead_algorithms_round_trip() {
    for aead in [
        CoreAead::Aes128Gcm,
        CoreAead::Aes192Gcm,
        CoreAead::Aes256Gcm,
        CoreAead::Aes256GcmSiv,
        CoreAead::ChaCha20Poly1305,
        CoreAead::XChaCha20Poly1305,
    ] {
        assert_eq!(CoreAead::try_from(ProtoAead::from(aead)).unwrap(), aead);
    }
}

#[test]
fn hash_algorithms_round_trip() {
    for hash in [
        CoreHash::Sha2_256,
        CoreHash::Sha2_384,
        CoreHash::Sha2_512,
        CoreHash::Sha3_224,
        CoreHash::Sha3_256,
        CoreHash::Sha3_384,
        CoreHash::Sha3_512,
    ] {
        assert_eq!(CoreHash::try_from(ProtoHash::from(hash)).unwrap(), hash);
    }
}

#[test]
fn reserved_and_unspecified_identifiers_are_rejected() {
    assert!(Algorithm::try_from(SignatureAlgorithm::SIGNATURE_ALGORITHM_UNSPECIFIED).is_err());
    assert!(
        Algorithm::try_from(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED).is_err()
    );
    assert!(Algorithm::try_from(KemAlgorithm::KEM_ALGORITHM_UNSPECIFIED).is_err());
    assert!(Algorithm::try_from(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256
    )
    .is_err());
    assert!(Algorithm::try_from(
        SignatureAlgorithm::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256
    )
    .is_err());
}
