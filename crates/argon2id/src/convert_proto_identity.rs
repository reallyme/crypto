// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity-only protobuf adapters; primitive inputs and operations are unchanged.

use crypto_proto::convert::UnsupportedProtoAlgorithm;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2idKdfVersion, CryptoArgon2idProfileIdentifier,
};

use crate::{Argon2KdfVersion, Argon2Profile};

impl TryFrom<&CryptoArgon2idProfileIdentifier> for Argon2Profile {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoArgon2idProfileIdentifier) -> Result<Self, Self::Error> {
        match identifier.kdf_version.as_known() {
            Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1) => Ok(Self::V1),
            Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2) => Ok(Self::V2),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<Argon2Profile> for CryptoArgon2idProfileIdentifier {
    fn from(value: Argon2Profile) -> Self {
        // Exhaustive native matching makes a newly introduced variant require
        // a reviewed schema mapping without changing existing discriminants.
        let identity = match value {
            Argon2Profile::V1 => Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1,
            Argon2Profile::V2 => Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2,
        };
        Self {
            kdf_version: identity.into(),
        }
    }
}

impl TryFrom<&CryptoArgon2idProfileIdentifier> for Argon2KdfVersion {
    type Error = UnsupportedProtoAlgorithm;

    fn try_from(identifier: &CryptoArgon2idProfileIdentifier) -> Result<Self, Self::Error> {
        match identifier.kdf_version.as_known() {
            Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1) => Ok(Self::V1),
            Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2) => Ok(Self::V2),
            _ => Err(UnsupportedProtoAlgorithm),
        }
    }
}

impl From<Argon2KdfVersion> for CryptoArgon2idProfileIdentifier {
    fn from(value: Argon2KdfVersion) -> Self {
        // Exhaustive native matching makes a newly introduced variant require
        // a reviewed schema mapping without changing existing discriminants.
        let identity = match value {
            Argon2KdfVersion::V1 => Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1,
            Argon2KdfVersion::V2 => Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2,
        };
        Self {
            kdf_version: identity.into(),
        }
    }
}
