// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HMAC facade routes backed by the semantic MAC operation owner.

#[cfg(any(feature = "native", feature = "wasm"))]
use crypto_core::{CryptoError, MacAlgorithm};

pub use crypto_hmac::{
    HmacKey, HmacTag, HMAC_MAX_KEY_LENGTH, HMAC_SHA256_TAG_LENGTH, HMAC_SHA384_TAG_LENGTH,
    HMAC_SHA512_TAG_LENGTH,
};

/// Computes an HMAC tag through the operation layer.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn authenticate(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
) -> Result<HmacTag, CryptoError> {
    crate::operations::mac::authenticate_tag(algorithm, key.as_bytes(), message)
}

/// Verifies an HMAC tag through the operation layer.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn verify(
    algorithm: MacAlgorithm,
    key: &HmacKey,
    message: &[u8],
    expected_tag: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::mac::verify(algorithm, key.as_bytes(), message, expected_tag)
}
