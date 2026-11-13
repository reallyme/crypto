// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, data-free errors for public JWK operations.

/// Canonical crypto error returned by JWK validation and encoding.
pub use crypto_core::CryptoError as JwtError;

pub(crate) fn public_key_error(error: JwtError) -> JwtError {
    // The primitive's generic key rejection gains a precise public-key role at
    // this boundary. Preserve every other canonical reason, including backend
    // and provider failures, rather than obscuring it as malformed key input.
    if error == JwtError::PRIMITIVE_INVALID_KEY {
        JwtError::PRIMITIVE_INVALID_PUBLIC_KEY
    } else {
        error
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
