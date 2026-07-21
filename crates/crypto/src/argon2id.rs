// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Argon2id facade routes backed by the semantic KDF operation owner.

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind};

pub use crypto_argon2id::{
    resolve_mobile_profile_for_unlock, resolve_profile_params_for_platform,
    resolve_profile_params_with_caps, Argon2Caps, Argon2KdfVersion, Argon2ParamsProfile,
    Argon2PlatformClass, Argon2Profile, Argon2Salt, Argon2Secret, Argon2idDerivedKey,
    DeriveKeyRequest, ARGON2ID_DERIVED_KEY_LENGTH, ARGON2ID_SALT_MAX_LENGTH,
    ARGON2ID_SALT_MIN_LENGTH, ARGON2ID_SECRET_MAX_LENGTH, ARGON2ID_V1_LANES,
    ARGON2ID_V1_MEMORY_COST_KIB, ARGON2ID_V1_TIME_COST, ARGON2ID_V2_LANES,
    ARGON2ID_V2_MEMORY_COST_KIB, ARGON2ID_V2_TIME_COST,
};

/// Derives a 32-byte Argon2id key through the operation layer.
pub fn derive_key(request: &DeriveKeyRequest<'_>) -> Result<Argon2idDerivedKey, CryptoError> {
    crate::operations::kdf::derive_argon2id(request)
        .map_err(|error| crypto_error_from_operation_error(request.profile, error))
}

/// Derives a 32-byte Argon2id key for a public KDF profile version.
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

fn crypto_error_from_operation_error(
    profile: Argon2Profile,
    error: crate::operations::OperationError,
) -> CryptoError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => KdfFailureKind::InvalidSecretLength,
        crate::operations::OperationError::Primitive {
            reason:
                crate::operations::PrimitiveErrorReason::InvalidLength
                | crate::operations::PrimitiveErrorReason::LengthOverflow,
        } => KdfFailureKind::InvalidParams,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return CryptoError::Unsupported,
        _ => KdfFailureKind::DerivationFailed,
    };

    CryptoError::Kdf {
        algorithm: KdfAlgorithm::Argon2id,
        profile: profile.to_kdf_profile(),
        kind,
    }
}
