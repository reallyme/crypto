// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{EcdsaCurve, EcdsaEncoding, EcdsaError};

// Two sign octets, two INTEGER headers and the widest SEQUENCE length header.
const MAX_DER_OVERHEAD: usize = 9;
const DER_PAIR_DEPTH: usize = 1;
const DER_PAIR_ELEMENTS: usize = 3;

/// Convert strict DER to fixed-width `r || s`, validating nonzero scalar ranges.
/// This changes only representation and retains high-S values.
pub fn der_to_fixed(curve: EcdsaCurve, signature: &[u8]) -> Result<Vec<u8>, EcdsaError> {
    validate_length(curve, signature, EcdsaEncoding::Der)?;
    let width = curve.scalar_len()?;
    let output_len = width.checked_mul(2).ok_or(EcdsaError::InvalidSignature)?;
    let maximum = output_len
        .checked_add(MAX_DER_OVERHEAD)
        .ok_or(EcdsaError::InvalidSignature)?;
    let limits = codec_der::der::DerLimits::new(maximum, DER_PAIR_DEPTH, DER_PAIR_ELEMENTS, width)
        .map_err(|_| EcdsaError::InvalidSignature)?;
    let pair = codec_der::der::decode_unsigned_integer_pair(signature, limits)
        .map_err(|_| EcdsaError::InvalidSignature)?;
    let mut fixed = Vec::new();
    fixed
        .try_reserve_exact(output_len)
        .map_err(|_| EcdsaError::AllocationFailed)?;
    fixed.resize(output_len, 0);
    for (end, magnitude) in [(width, pair.first()), (output_len, pair.second())] {
        let start = end
            .checked_sub(magnitude.len())
            .ok_or(EcdsaError::InvalidSignature)?;
        fixed
            .get_mut(start..end)
            .ok_or(EcdsaError::InvalidSignature)?
            .copy_from_slice(magnitude);
    }
    // Codec establishes canonical syntax, not the curve's scalar domain.
    // Reuse the existing range checks without normalizing high-S signatures.
    fixed_to_der(curve, &fixed)?;
    Ok(fixed)
}

/// Convert fixed-width `r || s` to canonical DER after scalar validation.
pub fn fixed_to_der(curve: EcdsaCurve, signature: &[u8]) -> Result<Vec<u8>, EcdsaError> {
    validate_length(curve, signature, EcdsaEncoding::FixedWidth)?;
    match curve {
        EcdsaCurve::P256 => crypto_p256::p256_ecdsa_jose_signature_to_der(signature)
            .map_err(|_| EcdsaError::InvalidSignature),
        EcdsaCurve::P384 => p384::ecdsa::Signature::from_slice(signature)
            .map(|value| value.to_der().as_bytes().to_vec())
            .map_err(|_| EcdsaError::InvalidSignature),
        EcdsaCurve::P521 => p521::ecdsa::Signature::from_slice(signature)
            .map(|value| value.to_der().as_bytes().to_vec())
            .map_err(|_| EcdsaError::InvalidSignature),
        #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
        curve => super::brainpool::fixed_to_der(curve, signature),
        #[cfg(all(
            feature = "brainpool",
            not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
        ))]
        curve => super::portable_brainpool::fixed_to_der(curve, signature),
        #[cfg(not(any(
            feature = "brainpool",
            all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
        )))]
        _ => Err(EcdsaError::UnsupportedCurve),
    }
}

pub(super) fn validate_length(
    curve: EcdsaCurve,
    bytes: &[u8],
    encoding: EcdsaEncoding,
) -> Result<(), EcdsaError> {
    const MIN_DER_SIGNATURE_LEN: usize = 8;
    let raw_length = curve
        .scalar_len()?
        .checked_mul(2)
        .ok_or(EcdsaError::InvalidSignature)?;
    let valid = match encoding {
        EcdsaEncoding::FixedWidth => bytes.len() == raw_length,
        EcdsaEncoding::Der => {
            let maximum = raw_length
                .checked_add(MAX_DER_OVERHEAD)
                .ok_or(EcdsaError::InvalidSignature)?;
            (MIN_DER_SIGNATURE_LEN..=maximum).contains(&bytes.len())
        }
    };
    if valid {
        Ok(())
    } else {
        Err(EcdsaError::InvalidSignature)
    }
}

pub(super) fn encode(
    curve: EcdsaCurve,
    der: Vec<u8>,
    encoding: EcdsaEncoding,
) -> Result<Vec<u8>, EcdsaError> {
    match encoding {
        EcdsaEncoding::Der => Ok(der),
        EcdsaEncoding::FixedWidth => der_to_fixed(curve, &der),
    }
}
