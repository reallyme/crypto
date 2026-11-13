// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroizing;

use crate::material::{
    HkdfInfo, HkdfInputKeyMaterial, HkdfOutput, HkdfSalt, HkdfSha384Prk, HKDF_SHA384_PRK_LENGTH,
};

/// Maximum output length permitted by RFC 5869 for HKDF-SHA384.
pub const HKDF_SHA384_MAX_OUTPUT_LENGTH: usize =
    crypto_core::contract_constants::hkdf::HKDF_SHA384_MAX_OUTPUT_LENGTH;

/// Runs the HKDF-SHA384 extract step and returns its fixed-size secret PRK.
pub fn extract_sha384(
    salt: Option<&HkdfSalt>,
    ikm: &HkdfInputKeyMaterial,
) -> Result<HkdfSha384Prk, CryptoError> {
    if ikm.as_bytes().is_empty() {
        return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_KEY);
    }

    let (prk, _) = Hkdf::<Sha384>::extract(salt.map(HkdfSalt::as_bytes), ikm.as_bytes());
    // Extract returns a separate PRK copy in addition to the HMAC state.
    // Wipe that copy after transferring it to the typed secret owner.
    let prk = Zeroizing::new(prk);
    let mut output = HkdfSha384Prk::from_array([0u8; HKDF_SHA384_PRK_LENGTH]);
    output.as_mut_bytes().copy_from_slice(prk.as_ref());
    Ok(output)
}

/// Runs HKDF-SHA384 expand from an extracted PRK.
pub fn expand_sha384<const N: usize>(
    prk: &HkdfSha384Prk,
    info: &HkdfInfo,
) -> Result<HkdfOutput<N>, CryptoError> {
    if N == 0 || N > HKDF_SHA384_MAX_OUTPUT_LENGTH {
        return Err(crypto_core::CryptoError::PRIMITIVE_INVALID_LENGTH);
    }

    let hkdf = Hkdf::<Sha384>::from_prk(prk.as_bytes())
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)?;
    // Expansion writes through the clearing owner on both success and error.
    let mut output = HkdfOutput::from_array([0u8; N]);
    hkdf.expand(info.as_bytes(), output.as_mut_bytes())
        .map_err(|_| crypto_core::CryptoError::BACKEND_INTERNAL)?;
    Ok(output)
}
