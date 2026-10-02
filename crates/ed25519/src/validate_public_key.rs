// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, prime-subgroup Ed25519 public-key identity validation.

use crypto_core::CryptoError;
use curve25519_dalek::edwards::CompressedEdwardsY;

const PUBLIC_KEY_LENGTH: usize = 32;

/// Reject encodings that cannot identify a usable strict Ed25519 verifier key.
pub fn validate_public_key_identity(public_key: &[u8]) -> Result<(), CryptoError> {
    let encoded: &[u8; PUBLIC_KEY_LENGTH] =
        public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let point = CompressedEdwardsY(*encoded)
        .decompress()
        .ok_or(CryptoError::InvalidKey)?;
    // Decompression alone may admit a second byte string for the same point.
    // Identity envelopes must name one prime-subgroup point exactly once.
    if point.compress().to_bytes() != *encoded || !point.is_torsion_free() || point.is_small_order()
    {
        return Err(CryptoError::InvalidKey);
    }
    Ok(())
}
