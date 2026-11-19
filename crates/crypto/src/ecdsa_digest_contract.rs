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
    #[cfg(any(feature = "p256", feature = "p384"))]
    let verified = crate::operations::signature::verify_ecdsa_digest_der(
        algorithm,
        &request.public_key,
        &request.digest,
        &request.signature,
    );
    // The contract remains available without providers so reduced builds can
    // reject requests deterministically without enabling an algorithm.
    #[cfg(not(any(feature = "p256", feature = "p384")))]
    let verified: Result<(), CryptoError> = {
        let _ = algorithm;
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    };
    verified?;
    Ok(CryptoNativeVerificationResult {
        status: CryptoVerificationStatus::CRYPTO_VERIFICATION_STATUS_VALID.into(),
    })
}
