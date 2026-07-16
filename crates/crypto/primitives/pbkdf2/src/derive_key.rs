// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::CryptoError;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};

use crate::types::{
    validate_output_len, Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Salt,
};

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
    let mut output = vec![0u8; request.output_len];
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
    Ok(Pbkdf2Output::from_vec(output))
}
