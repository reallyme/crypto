// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for MAC operations.

use crypto_core::MacAlgorithm;
#[cfg(feature = "hmac")]
use crypto_core::{CryptoError, MacFailureKind};

#[cfg(feature = "hmac")]
use super::{BackendErrorReason, PrimitiveErrorReason};
use super::{OperationError, ProviderErrorReason};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Computes a MAC tag for the selected algorithm.
///
/// The operation layer owns MAC algorithm selection so adapter boundaries route
/// through one typed error contract instead of duplicating HMAC semantics.
pub fn authenticate(
    algorithm: MacAlgorithm,
    key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::MacAuthenticate);
    #[cfg(feature = "hmac")]
    {
        authenticate_tag(algorithm, key, message).map(crypto_hmac::HmacTag::into_vec)
    }

    #[cfg(not(feature = "hmac"))]
    {
        let _ = (algorithm, key, message);
        unsupported_mac()
    }
}

/// Verifies a MAC tag for the selected algorithm.
pub fn verify(
    algorithm: MacAlgorithm,
    key: &[u8],
    message: &[u8],
    tag: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::MacVerify);
    #[cfg(feature = "hmac")]
    {
        let key = hmac_key_from_slice(key)?;
        crypto_hmac::verify(algorithm, &key, message, tag).map_err(map_hmac_error)
    }

    #[cfg(not(feature = "hmac"))]
    {
        let _ = (algorithm, key, message, tag);
        unsupported_mac()
    }
}

#[cfg(feature = "hmac")]
/// Computes a MAC tag while preserving the historical HMAC tag wrapper.
pub fn authenticate_tag(
    algorithm: MacAlgorithm,
    key: &[u8],
    message: &[u8],
) -> Result<crypto_hmac::HmacTag, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::MacAuthenticate);
    let key = hmac_key_from_slice(key)?;
    crypto_hmac::authenticate(algorithm, &key, message).map_err(map_hmac_error)
}

#[cfg(feature = "hmac")]
fn hmac_key_from_slice(key: &[u8]) -> Result<crypto_hmac::HmacKey, OperationError> {
    crypto_hmac::HmacKey::from_slice(key).map_err(map_hmac_error)
}

#[cfg(feature = "hmac")]
fn map_hmac_error(error: CryptoError) -> OperationError {
    match error {
        CryptoError::Mac {
            kind: MacFailureKind::InvalidKeyLength,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        },
        CryptoError::Mac {
            kind: MacFailureKind::InvalidTagLength,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        },
        CryptoError::Mac {
            kind: MacFailureKind::VerificationFailed,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        },
        CryptoError::Mac {
            kind: MacFailureKind::BackendFailure,
            ..
        } => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
        CryptoError::Unsupported => OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        },
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}

#[cfg(not(feature = "hmac"))]
fn unsupported_mac<T>() -> Result<T, OperationError> {
    Err(OperationError::Provider {
        reason: ProviderErrorReason::UnsupportedAlgorithm,
    })
}
