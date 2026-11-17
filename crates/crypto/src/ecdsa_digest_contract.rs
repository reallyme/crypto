// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected PKI ECDSA digest verification without device low-S policy changes.
use crypto_core::{Algorithm, CryptoError};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoEcdsaDigestVerifyRequest, CryptoNativeVerificationResult, CryptoVerificationStatus,
};

/// Executes the generated contract through the native semantic owner.
pub fn verify(
    request: &CryptoEcdsaDigestVerifyRequest,
) -> Result<CryptoNativeVerificationResult, CryptoError> {
    let algorithm = Algorithm::try_from(
        request
            .algorithm
            .as_option()
            .ok_or(CryptoError::PRIMITIVE_INVALID_PARAMETER)?,
    )
    .map_err(|_| CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)?;
    crate::operations::signature::verify_ecdsa_digest_der(
        algorithm,
        &request.public_key,
        &request.digest,
        &request.signature,
    )?;
    Ok(CryptoNativeVerificationResult {
        status: CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID.into(),
    })
}
