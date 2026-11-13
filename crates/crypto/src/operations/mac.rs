// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic owner for MAC operations.

use crypto_core::MacAlgorithm;

use super::OperationError;
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
        crypto_hmac::verify(algorithm, &key, message, tag)
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
    crypto_hmac::authenticate(algorithm, &key, message)
}

#[cfg(all(feature = "hmac", any(feature = "native", feature = "wasm")))]
fn hmac_key_from_slice(key: &[u8]) -> Result<crypto_hmac::HmacKey, OperationError> {
    crypto_hmac::HmacKey::from_slice(key)
}

#[cfg(not(all(feature = "hmac", any(feature = "native", feature = "wasm"))))]
fn unsupported_mac<T>() -> Result<T, OperationError> {
    Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
}
