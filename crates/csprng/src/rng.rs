// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, RngOutputKind};
use getrandom::{rand_core::TryRng, SysRng};

/// A source of cryptographically secure random bytes.
pub trait SecureRandom {
    /// Fills `output` with secure random bytes, tagging any error with `kind`.
    /// Returns an error if entropy is unavailable.
    fn fill_secure(&mut self, output: &mut [u8], kind: RngOutputKind) -> Result<(), CryptoError>;
}

/// [`SecureRandom`] implementation backed by the operating system's CSPRNG.
#[derive(Default)]
pub struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        SysRng
            .try_fill_bytes(output)
            .map_err(|_| crypto_core::CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}
