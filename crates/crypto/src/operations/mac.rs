// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic owner for MAC operations.

use crypto_core::MacAlgorithm;
#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
use crypto_core::{CryptoError, MacFailureKind};

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
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
    #[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
    {
        authenticate_tag(algorithm, key, message).map(crypto_hmac::HmacTag::into_vec)
    }

    #[cfg(not(all(feature = "hmac", any(feature = "native", feature = "wasm"))))]
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
    #[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
    {
        let key = hmac_key_from_slice(key)?;
        crypto_hmac::verify(algorithm, &key, message, tag).map_err(map_hmac_error)
    }

    #[cfg(not(all(feature = "hmac", any(feature = "native", feature = "wasm"))))]
    {
        let _ = (algorithm, key, message, tag);
        unsupported_mac()
    }
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
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

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
fn hmac_key_from_slice(key: &[u8]) -> Result<crypto_hmac::HmacKey, OperationError> {
    crypto_hmac::HmacKey::from_slice(key).map_err(map_hmac_error)
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
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

#[cfg(not(all(feature = "hmac", any(feature = "native", feature = "wasm"))))]
fn unsupported_mac<T>() -> Result<T, OperationError> {
    Err(OperationError::Provider {
        reason: ProviderErrorReason::UnsupportedAlgorithm,
    })
}
