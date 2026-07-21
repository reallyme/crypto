// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! KMAC facade routes backed by the semantic KDF operation owner.

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};

pub use crypto_kmac::{
    Kmac256Key, Kmac256Output, KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH,
    KMAC256_MAX_KEY_LENGTH, KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};

/// Derives KMAC256 output through the operation layer.
pub fn derive_kmac256(
    key: &Kmac256Key,
    context: &[u8],
    customization: &[u8],
    output_length: usize,
) -> Result<Kmac256Output, CryptoError> {
    crate::operations::kdf::derive_kmac256(key, context, customization, output_length)
        .map_err(crypto_error_from_operation_error)
}

fn crypto_error_from_operation_error(error: crate::operations::OperationError) -> CryptoError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => KdfFailureKind::InvalidSecretLength,
        crate::operations::OperationError::Primitive {
            reason:
                crate::operations::PrimitiveErrorReason::InvalidLength
                | crate::operations::PrimitiveErrorReason::LengthOverflow,
        } => KdfFailureKind::InvalidOutputLength,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return CryptoError::Unsupported,
        _ => KdfFailureKind::DerivationFailed,
    };

    CryptoError::Kdf {
        algorithm: KdfAlgorithm::Kmac256,
        profile: KdfProfile::Sp800185Kmac256,
        kind,
    }
}
