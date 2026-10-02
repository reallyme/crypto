// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::constants::{
    PBKDF2_MAX_HMAC_EVALUATIONS, PBKDF2_SHA256_OUTPUT_LENGTH, PBKDF2_SHA512_OUTPUT_LENGTH,
};
use crate::types::{
    kdf_error, validate_output_len, Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf,
    Pbkdf2Salt,
};
use crypto_core::KdfFailureKind;

/// PBKDF2 derivation request.
pub struct Pbkdf2Request<'a> {
    /// PRF suite.
    pub prf: Pbkdf2Prf,
    /// Password/secret input.
    pub password: &'a Pbkdf2Password,
    /// Salt input.
    pub salt: &'a Pbkdf2Salt,
    /// Iteration count.
    pub iterations: Pbkdf2Iterations,
    /// Desired output length in bytes.
    pub output_len: usize,
}

/// Derives PBKDF2 output keying material.
pub fn derive_key(request: &Pbkdf2Request<'_>) -> Result<Pbkdf2Output, CryptoError> {
    validate_output_len(request.output_len, request.prf)?;
    let digest_length = match request.prf {
        Pbkdf2Prf::HmacSha256 => PBKDF2_SHA256_OUTPUT_LENGTH,
        Pbkdf2Prf::HmacSha512 => PBKDF2_SHA512_OUTPUT_LENGTH,
    };
    let blocks = request
        .output_len
        .checked_add(digest_length - 1)
        .and_then(|length| length.checked_div(digest_length))
        .ok_or_else(|| kdf_error(request.prf, KdfFailureKind::ResourceLimitExceeded))?;
    let total_evaluations = u64::from(request.iterations.as_u32())
        .checked_mul(
            u64::try_from(blocks)
                .map_err(|_| kdf_error(request.prf, KdfFailureKind::ResourceLimitExceeded))?,
        )
        .ok_or_else(|| kdf_error(request.prf, KdfFailureKind::ResourceLimitExceeded))?;
    if total_evaluations > PBKDF2_MAX_HMAC_EVALUATIONS {
        return Err(kdf_error(
            request.prf,
            KdfFailureKind::ResourceLimitExceeded,
        ));
    }
    // Install drop-time cleanup before the backend writes derived key material.
    // This also covers unwinding or future early-return paths in this function.
    let mut output = Zeroizing::new(vec![0u8; request.output_len]);
    match request.prf {
        Pbkdf2Prf::HmacSha256 => pbkdf2_hmac::<Sha256>(
            request.password.as_bytes(),
            request.salt.as_bytes(),
            request.iterations.as_u32(),
            &mut output,
        ),
        Pbkdf2Prf::HmacSha512 => pbkdf2_hmac::<Sha512>(
            request.password.as_bytes(),
            request.salt.as_bytes(),
            request.iterations.as_u32(),
            &mut output,
        ),
    }
    Ok(Pbkdf2Output::from_zeroizing(output))
}
