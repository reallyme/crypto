// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JWA Concat KDF facade routes backed by the semantic KDF operation owner.

use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};

pub use crypto_concat_kdf::{
    JwaAlgorithmId, JwaConcatKdfOutput, JwaConcatKdfRequest, JwaPartyInfo, JwaSharedSecret,
    JWA_CONCAT_KDF_MAX_INFO_LENGTH, JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH,
    JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH,
};

/// Derives fixed-length JWA ECDH-ES Concat KDF output through the operation layer.
pub fn derive_jwa_concat_kdf_sha256<const N: usize>(
    request: &JwaConcatKdfRequest<'_>,
) -> Result<JwaConcatKdfOutput<N>, CryptoError> {
    crate::operations::kdf::derive_jwa_concat_kdf_sha256::<N>(request)
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
        algorithm: KdfAlgorithm::ConcatKdf,
        profile: KdfProfile::JwaEcdhEsSha256,
        kind,
    }
}
