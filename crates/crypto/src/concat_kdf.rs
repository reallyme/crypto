// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JWA Concat KDF facade routes backed by the semantic KDF operation owner.

use crypto_core::CryptoError;

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
}
