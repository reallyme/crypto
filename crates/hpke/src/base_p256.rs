// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded, single-record RFC 9180 Base/P-256/HKDF-SHA256/AES-128-GCM.
//!
//! `info` is borrowed verbatim. This interface uses empty AAD; the generic HPKE
//! interfaces remain available for applications that require nonempty AAD.
//! Successful opening authenticates the ciphertext under this recipient and
//! context. It does not authenticate a sender or establish document trust.

mod crypt;
mod key;
mod plaintext;
mod storage;

use thiserror::Error;

pub use crypt::{open, seal, seal_with_rng, P256BaseSealed};
pub use key::P256RecipientKey;
pub use plaintext::P256BasePlaintext;

/// Maximum `info` length, below the engine's inclusive key-schedule limit.
pub const INFO_MAX_LEN: usize = 65_530;
/// Local single-record plaintext bound in bytes.
pub const PLAINTEXT_MAX_LEN: usize = 16_777_216;
/// RFC 9180 uncompressed P-256 public/encapsulated key length.
pub const PUBLIC_KEY_LEN: usize = 65;
/// RFC 9180 P-256 private scalar length.
pub const PRIVATE_KEY_LEN: usize = 32;
/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// Stable failures for the bounded Base-mode interface.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum P256BaseError {
    /// The recipient scalar is not a valid 32-byte P-256 private key.
    #[error("invalid recipient private key")]
    InvalidPrivateKey,
    /// The recipient key is not a valid uncompressed P-256 point.
    #[error("invalid recipient public key")]
    InvalidPublicKey,
    /// `enc` is not a valid 65-byte uncompressed P-256 point.
    #[error("invalid encapsulated key")]
    InvalidEncapsulatedKey,
    /// A caller input exceeds this interface's documented bound.
    #[error("input exceeds bound")]
    InputTooLong,
    /// The ciphertext cannot contain a complete authentication tag.
    #[error("truncated ciphertext")]
    TruncatedCiphertext,
    /// Buffer allocation failed before sensitive input was copied.
    #[error("allocation failed")]
    AllocationFailed,
    /// The entropy provider failed; partially filled entropy is cleared.
    #[error("randomness unavailable")]
    RandomnessUnavailable,
    /// Authentication failed or the context does not match.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The reviewed backend could not complete the operation.
    #[error("provider failed")]
    ProviderFailed,
}

/// Injectable cryptographic entropy source. Implementations must supply fresh,
/// unpredictable bytes on every successful call.
pub trait P256BaseRng {
    /// Fill all requested bytes, or return a fixed randomness failure.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError>;
}

/// Entropy failure without provider text or diagnostic data.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum P256BaseRandomError {
    /// Entropy could not be supplied.
    #[error("randomness unavailable")]
    Unavailable,
}

struct SystemRandom;

impl P256BaseRng for SystemRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
        getrandom::fill(output).map_err(|_| P256BaseRandomError::Unavailable)
    }
}

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm128;

#[cfg(test)]
mod tests;
