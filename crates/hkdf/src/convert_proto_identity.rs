// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity-only protobuf adapters; primitive inputs and operations are unchanged.

use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfSuiteIdentifier, HashAlgorithm,
};

use crate::HkdfSuite;

impl TryFrom<&CryptoHkdfSuiteIdentifier> for HkdfSuite {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoHkdfSuiteIdentifier) -> Result<Self, Self::Error> {
        // Unknown modifiers must not be silently stripped from a recognized
        // identity. The decoded clearing owner retains them on this error path.
        if !identifier.__buffa_unknown_fields.is_empty() {
            return Err(UnsupportedProtoAlgorithm);
        }
        match identifier.hash.as_known() {
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_256) => Ok(Self::Sha2_256),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA2_384) => Ok(Self::Sha2_384),
            Some(HashAlgorithm::HASH_ALGORITHM_SHA3_256) => Ok(Self::Sha3_256),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<HkdfSuite> for CryptoHkdfSuiteIdentifier {
    fn from(value: HkdfSuite) -> Self {
        // Exhaustive native matching makes a newly introduced variant require
        // a reviewed schema mapping without changing existing discriminants.
        let identity = match value {
            HkdfSuite::Sha2_256 => HashAlgorithm::HASH_ALGORITHM_SHA2_256,
            HkdfSuite::Sha2_384 => HashAlgorithm::HASH_ALGORITHM_SHA2_384,
            HkdfSuite::Sha3_256 => HashAlgorithm::HASH_ALGORITHM_SHA3_256,
        };
        Self {
            hash: identity.into(),
            __buffa_unknown_fields: Default::default(),
        }
    }
}
