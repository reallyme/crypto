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

/// Canonical schema-owned failure for the bounded Base-mode interface.
pub use crypto_core::CryptoError as P256BaseError;

/// Injectable cryptographic entropy source. Implementations must supply fresh,
/// unpredictable bytes on every successful call.
pub trait P256BaseRng {
    /// Fill all requested bytes, or return the canonical provider failure.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError>;
}

/// Canonical schema-owned failure returned by injected entropy providers.
pub use crypto_core::CryptoError as P256BaseRandomError;

struct SystemRandom;

impl P256BaseRng for SystemRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), P256BaseRandomError> {
        getrandom::fill(output).map_err(|_| P256BaseRandomError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm128;

#[cfg(test)]
mod tests;
