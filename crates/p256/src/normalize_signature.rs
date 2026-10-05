// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cmp::Ordering;

use crypto_core::CryptoError;

use crate::jose_signature::{
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_jose_signature_to_der, signature_encoding_error,
    validate_scalar, P256_CURVE_ORDER, P256_ECDSA_JOSE_SIGNATURE_LEN, SCALAR_LEN,
};

const P256_HALF_CURVE_ORDER: [u8; SCALAR_LEN] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Returns the canonical low-S form of a DER-encoded P-256 ECDSA signature.
///
/// The input must use canonical DER and contain nonzero `r` and `s` scalars
/// below the P-256 subgroup order. The result preserves `r` and replaces a
/// high `s` with `n - s`, where `n` is the subgroup order. This transform does
/// not authenticate the signature; callers must still verify it against the
/// exact message or digest that was signed.
pub fn normalize_p256_ecdsa_der_low_s(signature_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = p256_ecdsa_der_to_jose_signature(signature_der)?;
    let normalized = normalize_p256_ecdsa_jose_signature_low_s(&signature)?;
    p256_ecdsa_jose_signature_to_der(&normalized)
}

/// Returns the canonical low-S form of a P-256 JOSE `r || s` signature.
///
/// The input must contain exactly two nonzero, 32-byte big-endian scalars below
/// the P-256 subgroup order. The result preserves `r` and replaces a high `s`
/// with `n - s`. This transform does not authenticate the signature.
pub fn normalize_p256_ecdsa_jose_signature_low_s(
    signature: &[u8],
) -> Result<[u8; P256_ECDSA_JOSE_SIGNATURE_LEN], CryptoError> {
    let mut normalized = <[u8; P256_ECDSA_JOSE_SIGNATURE_LEN]>::try_from(signature)
        .map_err(|_| signature_encoding_error())?;
    validate_scalar(&normalized[..SCALAR_LEN])?;
    validate_scalar(&normalized[SCALAR_LEN..])?;
    let s = <&[u8; SCALAR_LEN]>::try_from(&signature[SCALAR_LEN..])
        .map_err(|_| signature_encoding_error())?;

    if s.as_slice().cmp(P256_HALF_CURVE_ORDER.as_slice()) == Ordering::Greater {
        let normalized_s = subtract_scalar(&P256_CURVE_ORDER, s)?;
        normalized[SCALAR_LEN..].copy_from_slice(&normalized_s);
    }
    Ok(normalized)
}

fn subtract_scalar(
    minuend: &[u8; SCALAR_LEN],
    subtrahend: &[u8; SCALAR_LEN],
) -> Result<[u8; SCALAR_LEN], CryptoError> {
    let mut difference = [0u8; SCALAR_LEN];
    let mut borrow = 0u16;

    for index in (0..SCALAR_LEN).rev() {
        let left = u16::from(minuend[index]);
        let right = u16::from(subtrahend[index])
            .checked_add(borrow)
            .ok_or_else(signature_encoding_error)?;
        let (value, next_borrow) = if left >= right {
            (left - right, 0)
        } else {
            (
                256u16
                    .checked_add(left)
                    .and_then(|value| value.checked_sub(right))
                    .ok_or_else(signature_encoding_error)?,
                1,
            )
        };
        difference[index] = u8::try_from(value).map_err(|_| signature_encoding_error())?;
        borrow = next_borrow;
    }

    if borrow != 0 {
        return Err(signature_encoding_error());
    }
    Ok(difference)
}
