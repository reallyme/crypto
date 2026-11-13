// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fallible entropy injection for protected key generation.

/// Cryptographic entropy source for key generation. A successful call must
/// fill the complete destination with fresh, unpredictable bytes.
pub trait KeyRng {
    /// Fill the destination or fail without exposing provider diagnostics.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), KeyRandomError>;
}

/// Canonical schema-defined entropy failure.
pub use crypto_core::CryptoError as KeyRandomError;

pub(crate) struct SystemKeyRng;

impl KeyRng for SystemKeyRng {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), KeyRandomError> {
        getrandom::fill(destination).map_err(|_| KeyRandomError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}
