// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity-only protobuf adapters; primitive inputs and operations are unchanged.

use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPbkdf2PrfIdentifier, MacAlgorithm,
};

use crate::Pbkdf2Prf;

impl TryFrom<&CryptoPbkdf2PrfIdentifier> for Pbkdf2Prf {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoPbkdf2PrfIdentifier) -> Result<Self, Self::Error> {
        match identifier.prf.as_known() {
            Some(MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256) => Ok(Self::HmacSha256),
            Some(MacAlgorithm::MAC_ALGORITHM_HMAC_SHA512) => Ok(Self::HmacSha512),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<Pbkdf2Prf> for CryptoPbkdf2PrfIdentifier {
    fn from(value: Pbkdf2Prf) -> Self {
        // Exhaustive native matching makes a newly introduced variant require
        // a reviewed schema mapping without changing existing discriminants.
        let identity = match value {
            Pbkdf2Prf::HmacSha256 => MacAlgorithm::MAC_ALGORITHM_HMAC_SHA256,
            Pbkdf2Prf::HmacSha512 => MacAlgorithm::MAC_ALGORITHM_HMAC_SHA512,
        };
        Self {
            prf: identity.into(),
        }
    }
}
