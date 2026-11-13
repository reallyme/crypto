// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compatibility bridges to the canonical schema-defined identities.
//!
//! The protobuf enums are the cross-language contract (Rust, TypeScript,
//! Swift, Kotlin all import them); [`crate::Algorithm`] and its
//! siblings are the runtime dispatch selectors. This module keeps the two
//! in lockstep:
//!
//! * **protobuf → internal** uses [`TryFrom`], because the contract
//!   deliberately declares identifiers that do not map to the operation-agnostic
//!   core key-type enum (for example RSA suites and BIP-340 Schnorr); those
//!   convert to [`Err`] rather than silently mapping to the wrong key shape.
//!   Dedicated operation adapters handle supported suite-specific contracts.
//! * **internal → protobuf** uses per-operation functions whose `match`
//!   arms are **exhaustive over [`crate::Algorithm`]**. Adding a new
//!   internal algorithm without giving it a protobuf identifier is a
//!   *compile error* here, which is what prevents the contract and the
//!   runtime from silently drifting apart.
//!
//! The internal [`Algorithm`](crate::Algorithm) is operation-agnostic
//! (a curve/key type), whereas the protobuf splits by operation, so a key
//! type such as P-256 maps into *both* the signature and key-agreement
//! protobuf enums.

mod identity;

use crate::{AeadAlgorithm as CoreAead, Algorithm, HashAlgorithm as CoreHash};

use crypto_proto::generated::proto::reallyme::crypto::v1::{
    AeadAlgorithm as ProtoAead, CryptoAlgorithmIdentifier, HashAlgorithm as ProtoHash,
    KemAlgorithm, KeyAgreementAlgorithm, SignatureAlgorithm,
};

/// Identity conversion failure uses the canonical schema reason.
pub use crypto_proto::convert::UnsupportedProtoAlgorithm;

// ---------------------------------------------------------------------------
// protobuf -> internal (fallible: suite identifiers may have no core key type)
// ---------------------------------------------------------------------------

impl TryFrom<SignatureAlgorithm> for Algorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: SignatureAlgorithm) -> Result<Self, Self::Error> {
        // Retain the published closed-enum conversion while routing every
        // identity decision through the total generated-message conversion.
        Self::try_from(&CryptoAlgorithmIdentifier {
            algorithm: Some(crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_algorithm_identifier::Algorithm::Signature(value.into())),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

impl TryFrom<KeyAgreementAlgorithm> for Algorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: KeyAgreementAlgorithm) -> Result<Self, Self::Error> {
        // Retain the published closed-enum conversion while routing every
        // identity decision through the total generated-message conversion.
        Self::try_from(&CryptoAlgorithmIdentifier {
            algorithm: Some(crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_algorithm_identifier::Algorithm::KeyAgreement(value.into())),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

impl TryFrom<KemAlgorithm> for Algorithm {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: KemAlgorithm) -> Result<Self, Self::Error> {
        // Retain the published closed-enum conversion while routing every
        // identity decision through the total generated-message conversion.
        Self::try_from(&CryptoAlgorithmIdentifier {
            algorithm: Some(crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_algorithm_identifier::Algorithm::Kem(value.into())),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

impl TryFrom<ProtoAead> for CoreAead {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: ProtoAead) -> Result<Self, Self::Error> {
        // Retain the published closed-enum conversion while routing every
        // identity decision through the total generated-message conversion.
        Self::try_from(&CryptoAlgorithmIdentifier {
            algorithm: Some(crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_algorithm_identifier::Algorithm::Aead(value.into())),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

impl TryFrom<ProtoHash> for CoreHash {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(value: ProtoHash) -> Result<Self, Self::Error> {
        // Retain the published closed-enum conversion while routing every
        // identity decision through the total generated-message conversion.
        Self::try_from(&CryptoAlgorithmIdentifier {
            algorithm: Some(crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_algorithm_identifier::Algorithm::Hash(value.into())),
            __buffa_unknown_fields: Default::default(),
        })
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
        Algorithm::SlhDsaSha2_128s => {
            Some(SignatureAlgorithm::SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S)
        }
        Algorithm::X25519
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::XWing768 => None,
    }
}

/// The protobuf key-agreement identifier for `algorithm`, or `None` if the
/// algorithm is not a (direct) key-agreement algorithm.
pub fn key_agreement_algorithm_to_proto(algorithm: Algorithm) -> Option<KeyAgreementAlgorithm> {
    match algorithm {
        Algorithm::X25519 => Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_X25519),
        Algorithm::P256 => Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P256_ECDH),
        Algorithm::P384 => Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P384_ECDH),
        Algorithm::P521 => Some(KeyAgreementAlgorithm::KEY_AGREEMENT_ALGORITHM_P521_ECDH),
        Algorithm::Ed25519
        | Algorithm::Secp256k1
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87
        | Algorithm::SlhDsaSha2_128s
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::XWing768 => None,
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
        Algorithm::Ed25519
        | Algorithm::X25519
        | Algorithm::P256
        | Algorithm::P384
        | Algorithm::P521
        | Algorithm::Secp256k1
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87
        | Algorithm::SlhDsaSha2_128s => None,
    }
}

impl From<CoreAead> for ProtoAead {
    fn from(value: CoreAead) -> Self {
        match value {
            CoreAead::Aes128Gcm => ProtoAead::AEAD_ALGORITHM_AES_128_GCM,
            CoreAead::Aes192Gcm => ProtoAead::AEAD_ALGORITHM_AES_192_GCM,
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
