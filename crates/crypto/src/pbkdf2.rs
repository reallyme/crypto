// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! PBKDF2 facade routes backed by the semantic KDF operation owner.

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};

pub use crypto_pbkdf2::{
    Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request, Pbkdf2Salt,
    PBKDF2_MAX_ITERATIONS, PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MAX_PASSWORD_LENGTH,
    PBKDF2_MAX_SALT_LENGTH, PBKDF2_MIN_OUTPUT_LENGTH, PBKDF2_MIN_PASSWORD_LENGTH,
    PBKDF2_MIN_SALT_LENGTH, PBKDF2_MODERN_MIN_ITERATIONS,
};

/// Derives PBKDF2 output through the operation layer's modern policy.
pub fn derive_key(request: &Pbkdf2Request<'_>) -> Result<Pbkdf2Output, CryptoError> {
    crate::operations::kdf::derive_pbkdf2(request)
        .map_err(|error| crypto_error_from_operation_error(request.prf, error))
}

fn crypto_error_from_operation_error(
    prf: Pbkdf2Prf,
    error: crate::operations::OperationError,
) -> CryptoError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => KdfFailureKind::InvalidSecretLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidLength,
        } => KdfFailureKind::InvalidOutputLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::LengthOverflow,
        } => KdfFailureKind::InvalidOutputLength,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return CryptoError::Unsupported,
        _ => KdfFailureKind::DerivationFailed,
    };

    CryptoError::Kdf {
        algorithm: KdfAlgorithm::Pbkdf2,
        profile: pbkdf2_profile(prf),
        kind,
    }
}

fn pbkdf2_profile(prf: Pbkdf2Prf) -> KdfProfile {
    match prf {
        Pbkdf2Prf::HmacSha256 => KdfProfile::Pbkdf2HmacSha256,
        Pbkdf2Prf::HmacSha512 => KdfProfile::Pbkdf2HmacSha512,
    }
}
