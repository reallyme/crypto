// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::P256_SHA256_DIGEST_LEN;

/// An owned, exactly 32-byte SHA-256 digest for P-256 ECDSA.
///
/// This type prevents an original message and an already-computed digest from
/// crossing the same byte-slice boundary. It deliberately does not implement
/// `Clone`, `Copy`, `Debug`, or `Display`, and it zeroizes its owned bytes on
/// drop because message digests can retain privacy-sensitive information.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
///
/// require_clone::<crypto_p256::P256Sha256Digest>();
/// ```
///
/// ```compile_fail
/// fn require_debug<T: core::fmt::Debug>() {}
///
/// require_debug::<crypto_p256::P256Sha256Digest>();
/// ```
///
/// ```compile_fail
/// fn require_display<T: core::fmt::Display>() {}
///
/// require_display::<crypto_p256::P256Sha256Digest>();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct P256Sha256Digest {
    bytes: [u8; P256_SHA256_DIGEST_LEN],
}

impl P256Sha256Digest {
    /// Takes ownership of an exactly sized SHA-256 digest.
    pub fn new(bytes: [u8; P256_SHA256_DIGEST_LEN]) -> Self {
        Self { bytes }
    }

    /// Validates and copies an existing SHA-256 digest into a zeroizing owner.
    ///
    /// The caller remains responsible for clearing the source buffer when it
    /// owns that storage and the digest has privacy sensitivity.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, P256Sha256DigestError> {
        let bytes = <[u8; P256_SHA256_DIGEST_LEN]>::try_from(bytes)
            .map_err(|_| P256Sha256DigestError::PRIMITIVE_INVALID_LENGTH)?;
        Ok(Self::new(bytes))
    }

    /// Borrows the fixed-width digest bytes.
    pub fn as_bytes(&self) -> &[u8; P256_SHA256_DIGEST_LEN] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for P256Sha256Digest {
    type Error = P256Sha256DigestError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(value)
    }
}

/// Canonical validation error for a typed P-256 SHA-256 digest.
pub use crypto_core::CryptoError as P256Sha256DigestError;
