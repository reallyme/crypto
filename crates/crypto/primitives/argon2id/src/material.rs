// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{
    ARGON2ID_DERIVED_KEY_LENGTH, ARGON2ID_SALT_MAX_LENGTH, ARGON2ID_SALT_MIN_LENGTH,
};
use crate::profile::Argon2Profile;

/// Secret input (e.g. password) to the Argon2id KDF.
///
/// Zeroizes its bytes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Argon2Secret {
    bytes: Vec<u8>,
}

impl Argon2Secret {
    /// Constructs a secret from raw bytes, returning an error if the input is
    /// empty. The `profile` is used only to tag any resulting error.
    pub fn from_slice(input: &[u8], profile: Argon2Profile) -> Result<Self, CryptoError> {
        if input.is_empty() {
            return Err(CryptoError::Kdf {
                algorithm: KdfAlgorithm::Argon2id,
                profile: profile.to_kdf_profile(),
                kind: KdfFailureKind::InvalidSecretLength,
            });
        }

        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    /// Returns a reference to the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Salt input to the Argon2id KDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Salt {
    bytes: Vec<u8>,
}

impl Argon2Salt {
    /// Constructs a salt from raw bytes, returning an error unless the length is
    /// within [`ARGON2ID_SALT_MIN_LENGTH`]..=[`ARGON2ID_SALT_MAX_LENGTH`]. The
    /// `profile` is used only to tag any resulting error.
    pub fn from_slice(input: &[u8], profile: Argon2Profile) -> Result<Self, CryptoError> {
        let length = input.len();
        if !(ARGON2ID_SALT_MIN_LENGTH..=ARGON2ID_SALT_MAX_LENGTH).contains(&length) {
            return Err(CryptoError::Kdf {
                algorithm: KdfAlgorithm::Argon2id,
                profile: profile.to_kdf_profile(),
                kind: KdfFailureKind::InvalidSaltLength,
            });
        }

        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    /// Returns a reference to the raw salt bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Key material derived by the Argon2id KDF.
///
/// Zeroizes its bytes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Argon2idDerivedKey {
    bytes: [u8; ARGON2ID_DERIVED_KEY_LENGTH],
}

impl Argon2idDerivedKey {
    /// Returns a reference to the raw derived key bytes.
    pub fn as_bytes(&self) -> &[u8; ARGON2ID_DERIVED_KEY_LENGTH] {
        &self.bytes
    }

    pub(crate) fn from_array(bytes: [u8; ARGON2ID_DERIVED_KEY_LENGTH]) -> Self {
        Self { bytes }
    }
}
