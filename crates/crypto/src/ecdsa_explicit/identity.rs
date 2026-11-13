// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema identities do not enable a curve backend or imply a signature suite.

use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::crypto_algorithm_identifier::Algorithm as Identity, CryptoAlgorithmIdentifier,
    CryptoEcdsaCurveIdentifier, EcdsaCurve as ProtoCurve, HashAlgorithm,
};

use super::{EcdsaCurve, EcdsaHash};

impl TryFrom<&CryptoEcdsaCurveIdentifier> for EcdsaCurve {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoEcdsaCurveIdentifier) -> Result<Self, Self::Error> {
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        let value = identifier
            .curve
            .as_known()
            .ok_or(UnsupportedProtoAlgorithm)?;
        // Identity recognition must not query execution-provider availability.
        match value {
            ProtoCurve::ECDSA_CURVE_NIST_P256 => Ok(Self::P256),
            ProtoCurve::ECDSA_CURVE_NIST_P384 => Ok(Self::P384),
            ProtoCurve::ECDSA_CURVE_NIST_P521 => Ok(Self::P521),
            ProtoCurve::ECDSA_CURVE_BRAINPOOL_P256R1 => Ok(Self::BrainpoolP256r1),
            ProtoCurve::ECDSA_CURVE_BRAINPOOL_P320R1 => Ok(Self::BrainpoolP320r1),
            ProtoCurve::ECDSA_CURVE_BRAINPOOL_P384R1 => Ok(Self::BrainpoolP384r1),
            ProtoCurve::ECDSA_CURVE_BRAINPOOL_P512R1 => Ok(Self::BrainpoolP512r1),
            ProtoCurve::ECDSA_CURVE_UNSPECIFIED => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<EcdsaCurve> for ProtoCurve {
    fn from(value: EcdsaCurve) -> Self {
        match value {
            EcdsaCurve::P256 => Self::ECDSA_CURVE_NIST_P256,
            EcdsaCurve::P384 => Self::ECDSA_CURVE_NIST_P384,
            EcdsaCurve::P521 => Self::ECDSA_CURVE_NIST_P521,
            EcdsaCurve::BrainpoolP256r1 => Self::ECDSA_CURVE_BRAINPOOL_P256R1,
            EcdsaCurve::BrainpoolP320r1 => Self::ECDSA_CURVE_BRAINPOOL_P320R1,
            EcdsaCurve::BrainpoolP384r1 => Self::ECDSA_CURVE_BRAINPOOL_P384R1,
            EcdsaCurve::BrainpoolP512r1 => Self::ECDSA_CURVE_BRAINPOOL_P512R1,
        }
    }
}

impl TryFrom<&CryptoAlgorithmIdentifier> for EcdsaHash {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoAlgorithmIdentifier) -> Result<Self, Self::Error> {
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        let Some(Identity::Hash(hash)) = identifier.algorithm.as_ref() else {
            return Err(UnsupportedProtoAlgorithm);
        };
        // Reusing the hash schema must not enable other registered digests.
        Self::try_from(*hash)
    }
}

impl From<EcdsaHash> for HashAlgorithm {
    fn from(hash: EcdsaHash) -> Self {
        match hash {
            EcdsaHash::Sha256 => Self::HASH_ALGORITHM_SHA2_256,
            EcdsaHash::Sha384 => Self::HASH_ALGORITHM_SHA2_384,
            EcdsaHash::Sha512 => Self::HASH_ALGORITHM_SHA2_512,
        }
    }
}

// One total enum conversion owns the representation mapping for every native
// contract; an absent or unknown wire representation cannot select a default.
impl TryFrom<buffa::EnumValue<crypto_proto::generated::proto::reallyme::crypto::v1::EcdsaEncoding>>
    for super::EcdsaEncoding
{
    type Error = UnsupportedProtoAlgorithm;
    fn try_from(
        value: buffa::EnumValue<
            crypto_proto::generated::proto::reallyme::crypto::v1::EcdsaEncoding,
        >,
    ) -> Result<Self, Self::Error> {
        use crypto_proto::generated::proto::reallyme::crypto::v1::EcdsaEncoding as Encoding;
        match value.as_known() {
            Some(Encoding::ECDSA_ENCODING_DER) => Ok(Self::Der),
            Some(Encoding::ECDSA_ENCODING_FIXED_WIDTH) => Ok(Self::FixedWidth),
            Some(Encoding::ECDSA_ENCODING_UNSPECIFIED) | None => Err(UnsupportedProtoAlgorithm),
        }
    }
}
impl From<super::EcdsaEncoding>
    for crypto_proto::generated::proto::reallyme::crypto::v1::EcdsaEncoding
{
    fn from(value: super::EcdsaEncoding) -> Self {
        match value {
            super::EcdsaEncoding::Der => Self::ECDSA_ENCODING_DER,
            super::EcdsaEncoding::FixedWidth => Self::ECDSA_ENCODING_FIXED_WIDTH,
        }
    }
}
impl TryFrom<buffa::EnumValue<HashAlgorithm>> for EcdsaHash {
    type Error = UnsupportedProtoAlgorithm;
    fn try_from(value: buffa::EnumValue<HashAlgorithm>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_256) => Ok(Self::Sha256),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_384) => Ok(Self::Sha384),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_512) => Ok(Self::Sha512),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}
