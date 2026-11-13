// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use subtle::ConstantTimeEq;

/// Compares two byte slices for equality in constant time (no early exit on the
/// first differing byte). Unequal lengths short-circuit to `false`; when lengths
/// match, the byte comparison itself does not leak content via timing.
#[must_use = "the comparison result must be checked"]
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.ct_eq(right).into()
}

/// Compares two equal-length (`N`-byte) arrays for equality in constant time
/// (non-short-circuiting comparison that does not leak content via timing).
#[must_use = "the comparison result must be checked"]
pub fn ct_eq_fixed<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    left.ct_eq(right).into()
}

/// Constant-time equality check that returns `Ok(())` when the slices are equal,
/// and an error otherwise: `LengthMismatch` if the lengths differ, or `NotEqual`
/// if equal-length contents differ. The content comparison is non-short-circuiting.
pub fn require_ct_eq(left: &[u8], right: &[u8]) -> Result<(), CryptoError> {
    if left.len() != right.len() {
        return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_LENGTH);
    }

    if ct_eq(left, right) {
        return Ok(());
    }

    Err(crypto_core::CryptoError::PRIMITIVE_VERIFICATION_FAILED)
}
