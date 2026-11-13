// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! PBKDF2 facade routes backed by the semantic KDF operation owner.

#[cfg(any(feature = "native", feature = "wasm"))]
use crypto_core::CryptoError;

pub use crypto_pbkdf2::{
    Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Salt, PBKDF2_MAX_ITERATIONS,
    PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MAX_PASSWORD_LENGTH, PBKDF2_MAX_SALT_LENGTH,
    PBKDF2_MIN_OUTPUT_LENGTH, PBKDF2_MIN_PASSWORD_LENGTH, PBKDF2_MIN_SALT_LENGTH,
    PBKDF2_MODERN_MIN_ITERATIONS,
};

#[cfg(any(feature = "native", feature = "wasm"))]
pub use crypto_pbkdf2::Pbkdf2Request;

/// Derives PBKDF2 output through the operation layer's modern policy.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn derive_key(request: &Pbkdf2Request<'_>) -> Result<Pbkdf2Output, CryptoError> {
    crate::operations::kdf::derive_pbkdf2(request)
        .map_err(|error| crypto_error_from_operation_error(request.prf, error))
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn crypto_error_from_operation_error(
    _prf: Pbkdf2Prf,
    error: crate::operations::OperationError,
) -> CryptoError {
    error
}
