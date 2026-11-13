// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! KMAC facade routes backed by the semantic KDF operation owner.

#[cfg(any(feature = "native", feature = "wasm"))]
use crypto_core::CryptoError;

pub use crypto_kmac::{
    Kmac256Key, Kmac256Output, KMAC256_MAX_CONTEXT_LENGTH, KMAC256_MAX_CUSTOMIZATION_LENGTH,
    KMAC256_MAX_KEY_LENGTH, KMAC256_MAX_OUTPUT_LENGTH, KMAC256_MIN_KEY_LENGTH,
};

/// Derives KMAC256 output through the operation layer.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn derive_kmac256(
    key: &Kmac256Key,
    context: &[u8],
    customization: &[u8],
    output_length: usize,
) -> Result<Kmac256Output, CryptoError> {
    crate::operations::kdf::derive_kmac256(key, context, customization, output_length)
        .map_err(crypto_error_from_operation_error)
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn crypto_error_from_operation_error(error: crate::operations::OperationError) -> CryptoError {
    error
}
