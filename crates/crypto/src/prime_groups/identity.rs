// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain identity conversion does not create secrets or select a backend.

use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPrimeGroupIdentifier, PrimeGroup as ProtoGroup,
};

use super::PrimeGroup;

impl TryFrom<&CryptoPrimeGroupIdentifier> for PrimeGroup {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoPrimeGroupIdentifier) -> Result<Self, Self::Error> {
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        let value = identifier
            .group
            .as_known()
            .ok_or(UnsupportedProtoAlgorithm)?;
        // Identity recognition must not query execution-provider availability.
        match value {
            ProtoGroup::PRIME_GROUP_NIST_P256 => Ok(Self::NistP256),
            ProtoGroup::PRIME_GROUP_NIST_P384 => Ok(Self::NistP384),
            ProtoGroup::PRIME_GROUP_NIST_P521 => Ok(Self::NistP521),
            ProtoGroup::PRIME_GROUP_BRAINPOOL_P256R1 => Ok(Self::BrainpoolP256r1),
            ProtoGroup::PRIME_GROUP_BRAINPOOL_P320R1 => Ok(Self::BrainpoolP320r1),
            ProtoGroup::PRIME_GROUP_BRAINPOOL_P384R1 => Ok(Self::BrainpoolP384r1),
            ProtoGroup::PRIME_GROUP_BRAINPOOL_P512R1 => Ok(Self::BrainpoolP512r1),
            ProtoGroup::PRIME_GROUP_RFC5114_DH1024_160 => Ok(Self::Rfc5114Dh1024_160),
            ProtoGroup::PRIME_GROUP_RFC5114_DH2048_224 => Ok(Self::Rfc5114Dh2048_224),
            ProtoGroup::PRIME_GROUP_RFC5114_DH2048_256 => Ok(Self::Rfc5114Dh2048_256),
            ProtoGroup::PRIME_GROUP_UNSPECIFIED => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<PrimeGroup> for ProtoGroup {
    fn from(value: PrimeGroup) -> Self {
        match value {
            PrimeGroup::NistP256 => Self::PRIME_GROUP_NIST_P256,
            PrimeGroup::NistP384 => Self::PRIME_GROUP_NIST_P384,
            PrimeGroup::NistP521 => Self::PRIME_GROUP_NIST_P521,
            PrimeGroup::BrainpoolP256r1 => Self::PRIME_GROUP_BRAINPOOL_P256R1,
            PrimeGroup::BrainpoolP320r1 => Self::PRIME_GROUP_BRAINPOOL_P320R1,
            PrimeGroup::BrainpoolP384r1 => Self::PRIME_GROUP_BRAINPOOL_P384R1,
            PrimeGroup::BrainpoolP512r1 => Self::PRIME_GROUP_BRAINPOOL_P512R1,
            PrimeGroup::Rfc5114Dh1024_160 => Self::PRIME_GROUP_RFC5114_DH1024_160,
            PrimeGroup::Rfc5114Dh2048_224 => Self::PRIME_GROUP_RFC5114_DH2048_224,
            PrimeGroup::Rfc5114Dh2048_256 => Self::PRIME_GROUP_RFC5114_DH2048_256,
        }
    }
}
