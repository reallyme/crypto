// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HMAC facade routes backed by the semantic MAC operation owner.

use crypto_core::{CryptoError, MacAlgorithm, MacFailureKind, MacHash};

pub use crypto_hmac::{
    HmacKey, HmacTag, HMAC_MAX_KEY_LENGTH, HMAC_SHA256_TAG_LENGTH, HMAC_SHA384_TAG_LENGTH,
    HMAC_SHA512_TAG_LENGTH,
};

/// Computes an HMAC tag through the operation layer.
pub fn authenticate(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
) -> Result<HmacTag, CryptoError> {
    crate::operations::mac::authenticate_tag(algorithm, key.as_bytes(), message)
        .map_err(|error| crypto_error_from_operation_error(algorithm, error))
}

/// Verifies an HMAC tag through the operation layer.
pub fn verify(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
    expected_tag: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::mac::verify(algorithm, key.as_bytes(), message, expected_tag)
        .map_err(|error| crypto_error_from_operation_error(algorithm, error))
}

fn crypto_error_from_operation_error(
    algorithm: MacAlgorithm,
    error: crate::operations::OperationError,
) -> CryptoError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => MacFailureKind::InvalidKeyLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidLength,
        } => MacFailureKind::InvalidTagLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::VerificationFailed,
        } => MacFailureKind::VerificationFailed,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return CryptoError::Unsupported,
        _ => MacFailureKind::BackendFailure,
    };

    CryptoError::Mac {
        hash: mac_hash(algorithm),
        kind,
    }
}

fn mac_hash(algorithm: MacAlgorithm) -> MacHash {
    match algorithm {
        MacAlgorithm::HmacSha256 => MacHash::Sha2_256,
        MacAlgorithm::HmacSha384 => MacHash::Sha2_384,
        MacAlgorithm::HmacSha512 => MacHash::Sha2_512,
    }
}
