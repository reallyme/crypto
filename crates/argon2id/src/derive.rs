// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use argon2::{Algorithm, Argon2, Block, Params, Version};
use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::ARGON2ID_DERIVED_KEY_LENGTH;
use crate::material::{Argon2Salt, Argon2Secret, Argon2idDerivedKey};
use crate::profile::{Argon2KdfVersion, Argon2Profile};

/// Inputs for a single Argon2id key-derivation operation.
pub struct DeriveKeyRequest<'a> {
    /// Parameter profile selecting the cost tuple.
    pub profile: Argon2Profile,
    /// Secret input (e.g. password) to hash.
    pub secret: &'a Argon2Secret,
    /// Salt to bind the derivation to.
    pub salt: &'a Argon2Salt,
}

/// Derives a 32-byte key with Argon2id using the request's profile, secret, and
/// salt. Returns an error on invalid parameters or derivation failure. The
/// intermediate output buffer is zeroized before returning.
pub fn derive_key(request: &DeriveKeyRequest<'_>) -> Result<Argon2idDerivedKey, CryptoError> {
    let profile = request.profile;
    let kdf_profile = profile.to_kdf_profile();
    let (m_cost, t_cost, p_cost) = profile.params_tuple();

    let params =
        Params::new(m_cost, t_cost, p_cost, Some(ARGON2ID_DERIVED_KEY_LENGTH)).map_err(|_| {
            CryptoError::Kdf {
                algorithm: KdfAlgorithm::Argon2id,
                profile: kdf_profile,
                kind: KdfFailureKind::InvalidParams,
            }
        })?;

    let block_count = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // The upstream convenience API allocates its memory matrix in an ordinary
    // Vec, which releases password-derived blocks without wiping them. Own the
    // matrix here so every initialized block is zeroized on success, failure,
    // or unwind before the allocation is returned to the allocator.
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: kdf_profile,
            kind: KdfFailureKind::DerivationFailed,
        })?;
    blocks.resize(block_count, Block::default());
    let mut blocks = Zeroizing::new(blocks);

    let mut output = Zeroizing::new(vec![0u8; ARGON2ID_DERIVED_KEY_LENGTH]);
    argon2
        .hash_password_into_with_memory(
            request.secret.as_bytes(),
            request.salt.as_bytes(),
            &mut output,
            blocks.as_mut_slice(),
        )
        .map_err(|_| CryptoError::Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            profile: kdf_profile,
            kind: KdfFailureKind::DerivationFailed,
        })?;

    let mut bytes = [0u8; ARGON2ID_DERIVED_KEY_LENGTH];
    bytes.copy_from_slice(&output);
    output.zeroize();

    Ok(Argon2idDerivedKey::from_array(bytes))
}

/// Derives a 32-byte key from raw secret and salt bytes, selecting the profile
/// from the KDF version integer. Returns an error if the version is unrecognized,
/// the secret or salt length is invalid, or derivation fails.
pub fn derive_key_for_version(
    kdf_version: u32,
    secret: &[u8],
    salt: &[u8],
) -> Result<Argon2idDerivedKey, CryptoError> {
    let version = Argon2KdfVersion::try_from(kdf_version)?;
    let profile = Argon2Profile::from(version);

    let secret = Argon2Secret::from_slice(secret, profile)?;
    let salt = Argon2Salt::from_slice(salt, profile)?;

    derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    })
}
