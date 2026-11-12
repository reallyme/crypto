// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fallible entropy injection for protected key generation.

use thiserror::Error;

/// Cryptographic entropy source for key generation. A successful call must
/// fill the complete destination with fresh, unpredictable bytes.
pub trait KeyRng {
    /// Fill the destination or fail without exposing provider diagnostics.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), KeyRandomError>;
}

/// Secret-free entropy failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum KeyRandomError {
    /// Cryptographic entropy could not be supplied.
    #[error("key randomness unavailable")]
    Unavailable,
}

pub(crate) struct SystemKeyRng;

impl KeyRng for SystemKeyRng {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), KeyRandomError> {
        getrandom::fill(destination).map_err(|_| KeyRandomError::Unavailable)
    }
}
