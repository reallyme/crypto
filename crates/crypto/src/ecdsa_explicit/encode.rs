// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{EcdsaCurve, EcdsaEncoding, EcdsaError};

/// Convert strict DER to fixed-width `r || s`, validating nonzero scalar ranges.
/// This changes only representation and retains high-S values.
pub fn der_to_fixed(curve: EcdsaCurve, signature: &[u8]) -> Result<Vec<u8>, EcdsaError> {
    validate_length(curve, signature, EcdsaEncoding::Der)?;
    match curve {
        EcdsaCurve::P256 => crypto_p256::p256_ecdsa_der_to_jose_signature(signature)
            .map(|bytes| bytes.to_vec())
            .map_err(|_| EcdsaError::InvalidSignature),
        EcdsaCurve::P384 => p384::ecdsa::Signature::from_der(signature)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|_| EcdsaError::InvalidSignature),
        EcdsaCurve::P521 => p521::ecdsa::Signature::from_der(signature)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|_| EcdsaError::InvalidSignature),
        #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
        curve => super::brainpool::der_to_fixed(curve, signature),
        #[cfg(all(
            feature = "brainpool",
            not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
        ))]
        curve => super::portable_brainpool::der_to_fixed(curve, signature),
        #[cfg(not(any(
            feature = "brainpool",
            all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
        )))]
        _ => Err(EcdsaError::UnsupportedCurve),
    }
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
    // Two possible sign octets, two INTEGER headers, and the SEQUENCE header
    // (including a long-form length for the widest supported signatures).
    const MAX_DER_OVERHEAD: usize = 9;
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
