// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Bridge between the generated protobuf algorithm identifiers and the
//! internal [`crypto_core`] enums.
//!
//! The protobuf enums are the cross-language contract (Rust, TypeScript,
//! Swift, Kotlin all import them); [`crypto_core::Algorithm`] and its
//! siblings are the runtime dispatch selectors. This module keeps the two
//! in lockstep:
//!
//! * **protobuf → internal** uses [`TryFrom`], because the contract
//!   deliberately declares identifiers ReallyMe does not yet implement
//!   (RSA signing, BIP-340 Schnorr, SLH-DSA, P-384/P-521 ECDH, …); those
//!   convert to [`Err`] rather than silently mapping to the wrong thing.
//! * **internal → protobuf** uses per-operation functions whose `match`
//!   arms are **exhaustive over [`crypto_core::Algorithm`]**. Adding a new
//!   internal algorithm without giving it a protobuf identifier is a
//!   *compile error* here, which is what prevents the contract and the
//!   runtime from silently drifting apart.
//!
//! The internal [`Algorithm`](crypto_core::Algorithm) is operation-agnostic
//! (a curve/key type), whereas the protobuf splits by operation, so a key
//! type such as P-256 maps into *both* the signature and key-agreement
//! protobuf enums.

use crypto_core::{AeadAlgorithm as CoreAead, Algorithm, HashAlgorithm as CoreHash};

use crate::generated::proto::reallyme::crypto::v1::{
    AeadAlgorithm as ProtoAead, HashAlgorithm as ProtoHash, KemAlgorithm, KeyAgreementAlgorithm,
    SignatureAlgorithm,
};

/// A protobuf algorithm identifier has no corresponding implemented
/// [`crypto_core`] algorithm.
///
/// This is returned for the `_UNSPECIFIED` sentinel and for identifiers the
/// contract reserves but this build does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("protobuf algorithm identifier is not a supported crypto-core algorithm")]
pub struct UnsupportedProtoAlgorithm;

// ---------------------------------------------------------------------------
// protobuf -> internal (fallible: reserved identifiers have no internal algo)
// ---------------------------------------------------------------------------

impl TryFrom<SignatureAlgorithm> for Algorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: SignatureAlgorithm) -> Result<Self, Self::Error> {
        match value {
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519 => Ok(Algorithm::Ed25519),
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 => Ok(Algorithm::P256),
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 => Ok(Algorithm::P384),
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512 => Ok(Algorithm::P521),
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 => {
                Ok(Algorithm::Secp256k1)
            }
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_44 => Ok(Algorithm::MlDsa44),
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_65 => Ok(Algorithm::MlDsa65),
            SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_87 => Ok(Algorithm::MlDsa87),
            // Reserved in the contract but not implemented here.
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl TryFrom<KeyAgreementAlgorithm> for Algorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: KeyAgreementAlgorithm) -> Result<Self, Self::Error> {
        match value {
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519 => Ok(Algorithm::X25519),
            KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH => Ok(Algorithm::P256),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl TryFrom<KemAlgorithm> for Algorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: KemAlgorithm) -> Result<Self, Self::Error> {
        match value {
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_512 => Ok(Algorithm::MlKem512),
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_768 => Ok(Algorithm::MlKem768),
            KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024 => Ok(Algorithm::MlKem1024),
            KemAlgorithm::KEM_ALGORITHM_X_WING_768 => Ok(Algorithm::XWing768),
            KemAlgorithm::KEM_ALGORITHM_X_WING_1024 => Ok(Algorithm::XWing1024),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl TryFrom<ProtoAead> for CoreAead {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: ProtoAead) -> Result<Self, Self::Error> {
        match value {
            ProtoAead::AEAD_ALGORITHM_AES_256_GCM => Ok(CoreAead::Aes256Gcm),
            ProtoAead::AEAD_ALGORITHM_AES_256_GCM_SIV => Ok(CoreAead::Aes256GcmSiv),
            ProtoAead::AEAD_ALGORITHM_CHACHA20_POLY1305 => Ok(CoreAead::ChaCha20Poly1305),
            ProtoAead::AEAD_ALGORITHM_XCHACHA20_POLY1305 => Ok(CoreAead::XChaCha20Poly1305),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl TryFrom<ProtoHash> for CoreHash {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: ProtoHash) -> Result<Self, Self::Error> {
        match value {
            ProtoHash::HASH_ALGORITHM_SHA2_256 => Ok(CoreHash::Sha2_256),
            ProtoHash::HASH_ALGORITHM_SHA2_384 => Ok(CoreHash::Sha2_384),
            ProtoHash::HASH_ALGORITHM_SHA2_512 => Ok(CoreHash::Sha2_512),
            ProtoHash::HASH_ALGORITHM_SHA3_224 => Ok(CoreHash::Sha3_224),
            ProtoHash::HASH_ALGORITHM_SHA3_256 => Ok(CoreHash::Sha3_256),
            ProtoHash::HASH_ALGORITHM_SHA3_384 => Ok(CoreHash::Sha3_384),
            ProtoHash::HASH_ALGORITHM_SHA3_512 => Ok(CoreHash::Sha3_512),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

// ---------------------------------------------------------------------------
// internal -> protobuf
//
// The `match`es below are exhaustive over `Algorithm` on purpose: adding a
// new internal algorithm forces every one of these functions to be updated,
// which is the compile-time guard against contract/runtime drift. Each
// returns `Some` only for the algorithms that participate in that operation
// (e.g. P-256 appears in both signatures and key agreement).
// ---------------------------------------------------------------------------

/// The protobuf signature identifier for `algorithm`, or `None` if the
/// algorithm is not a signature algorithm.
pub fn signature_algorithm_to_proto(algorithm: Algorithm) -> Option<SignatureAlgorithm> {
    match algorithm {
        Algorithm::Ed25519 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ED25519),
        Algorithm::P256 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256),
        Algorithm::P384 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P384_SHA384),
        Algorithm::P521 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P521_SHA512),
        Algorithm::Secp256k1 => {
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256)
        }
        Algorithm::MlDsa44 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_44),
        Algorithm::MlDsa65 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_65),
        Algorithm::MlDsa87 => Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_ML_DSA_87),
        Algorithm::X25519
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::XWing768
        | Algorithm::XWing1024 => None,
    }
}

/// The protobuf key-agreement identifier for `algorithm`, or `None` if the
/// algorithm is not a (direct) key-agreement algorithm.
pub fn key_agreement_algorithm_to_proto(algorithm: Algorithm) -> Option<KeyAgreementAlgorithm> {
    match algorithm {
        Algorithm::X25519 => Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519),
        Algorithm::P256 => Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH),
        Algorithm::Ed25519
        | Algorithm::P384
        | Algorithm::P521
        | Algorithm::Secp256k1
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::XWing768
        | Algorithm::XWing1024 => None,
    }
}

/// The protobuf KEM identifier for `algorithm`, or `None` if the algorithm
/// is not a KEM.
pub fn kem_algorithm_to_proto(algorithm: Algorithm) -> Option<KemAlgorithm> {
    match algorithm {
        Algorithm::MlKem512 => Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_512),
        Algorithm::MlKem768 => Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_768),
        Algorithm::MlKem1024 => Some(KemAlgorithm::KEM_ALGORITHM_ML_KEM_1024),
        Algorithm::XWing768 => Some(KemAlgorithm::KEM_ALGORITHM_X_WING_768),
        Algorithm::XWing1024 => Some(KemAlgorithm::KEM_ALGORITHM_X_WING_1024),
        Algorithm::Ed25519
        | Algorithm::X25519
        | Algorithm::P256
        | Algorithm::P384
        | Algorithm::P521
        | Algorithm::Secp256k1
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87 => None,
    }
}

impl From<CoreAead> for ProtoAead {
    fn from(value: CoreAead) -> Self {
        match value {
            CoreAead::Aes256Gcm => ProtoAead::AEAD_ALGORITHM_AES_256_GCM,
            CoreAead::Aes256GcmSiv => ProtoAead::AEAD_ALGORITHM_AES_256_GCM_SIV,
            CoreAead::ChaCha20Poly1305 => ProtoAead::AEAD_ALGORITHM_CHACHA20_POLY1305,
            CoreAead::XChaCha20Poly1305 => ProtoAead::AEAD_ALGORITHM_XCHACHA20_POLY1305,
        }
    }
}

impl From<CoreHash> for ProtoHash {
    fn from(value: CoreHash) -> Self {
        match value {
            CoreHash::Sha2_256 => ProtoHash::HASH_ALGORITHM_SHA2_256,
            CoreHash::Sha2_384 => ProtoHash::HASH_ALGORITHM_SHA2_384,
            CoreHash::Sha2_512 => ProtoHash::HASH_ALGORITHM_SHA2_512,
            CoreHash::Sha3_224 => ProtoHash::HASH_ALGORITHM_SHA3_224,
            CoreHash::Sha3_256 => ProtoHash::HASH_ALGORITHM_SHA3_256,
            CoreHash::Sha3_384 => ProtoHash::HASH_ALGORITHM_SHA3_384,
            CoreHash::Sha3_512 => ProtoHash::HASH_ALGORITHM_SHA3_512,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Every internal [`Algorithm`] variant. If a new variant is added the
    /// `_to_proto` matches above stop compiling first; this list is the
    /// second guard, ensuring the variant maps into at least one protobuf
    /// family (i.e. it is not accidentally `None` everywhere).
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
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
        Algorithm::XWing768,
        Algorithm::XWing1024,
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
        // The `_UNSPECIFIED` sentinel never maps to a real algorithm.
        assert!(Algorithm::try_from(SignatureAlgorithm::SIGNATURE_ALGORITHM_UNSPECIFIED).is_err());
        assert!(
            Algorithm::try_from(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_UNSPECIFIED)
                .is_err()
        );
        assert!(Algorithm::try_from(KemAlgorithm::KEM_ALGORITHM_UNSPECIFIED).is_err());
        // Contract-reserved but unimplemented identifiers fail closed.
        assert!(Algorithm::try_from(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256
        )
        .is_err());
        assert!(Algorithm::try_from(
            SignatureAlgorithm::SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256
        )
        .is_err());
        assert!(
            Algorithm::try_from(SignatureAlgorithm::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S).is_err()
        );
    }
}
