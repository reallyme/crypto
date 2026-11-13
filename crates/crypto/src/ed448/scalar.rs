// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_bigint::{U1024, U448};
use ed448_goldilocks::{elliptic_curve::scalar::FromUintUnchecked, EdwardsScalar, ORDER};
use zeroize::Zeroizing;

use super::{CryptoError, PUBLIC_KEY_LEN};

const WIDE_INTEGER_LEN: usize = 128;
const SCALAR_INTEGER_LEN: usize = 56;
const MOST_SIGNIFICANT_SCALAR_OCTET: usize = 55;
const UNUSED_SCALAR_BITS_MASK: u8 = 0xc0;

/// Reduction uses the fixed public group order and the constant-time bigint
/// operation. In particular, secret wide inputs never enter the curve
/// library's wide-byte decoder or its unprotected byte temporaries.
pub(super) fn reduce(bytes: &[u8]) -> Result<Zeroizing<EdwardsScalar>, CryptoError> {
    if bytes.len() > super::SIGNATURE_LEN {
        return Err(CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY);
    }
    let mut encoded = Zeroizing::new([0; WIDE_INTEGER_LEN]);
    encoded[..bytes.len()].copy_from_slice(bytes);
    let integer = Zeroizing::new(U1024::from_le_slice(encoded.as_ref()));
    let reduced = Zeroizing::new(integer.rem(ORDER.as_nz_ref()));
    // The remainder is strictly below ORDER. This constructor cannot reduce,
    // re-encode, or silently accept an out-of-range private scalar.
    Ok(Zeroizing::new(EdwardsScalar::from_uint_unchecked(*reduced)))
}

pub(super) fn decode_signature(bytes: &[u8]) -> Result<Zeroizing<EdwardsScalar>, CryptoError> {
    // RFC 8032 requires all ten unused bits to be clear, independently of the
    // backend's canonical decoder. Never discard a nonzero final octet.
    if bytes.len() != PUBLIC_KEY_LEN
        || bytes[SCALAR_INTEGER_LEN] != 0
        || bytes[MOST_SIGNIFICANT_SCALAR_OCTET] & UNUSED_SCALAR_BITS_MASK != 0
    {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    let integer = Zeroizing::new(U448::from_le_slice(&bytes[..SCALAR_INTEGER_LEN]));
    if *integer >= *ORDER.as_ref() {
        return Err(CryptoError::PRIMITIVE_INVALID_SIGNATURE);
    }
    Ok(Zeroizing::new(EdwardsScalar::from_uint_unchecked(*integer)))
}

#[cfg(test)]
#[path = "scalar_tests.rs"]
mod tests;
