// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::AlgorithmError;
use codec_multikey::{parse_multikey, validate_key_binding, KeyBindingInput};
use crypto_core::Algorithm;

/// Structural validation of a typed public-key binding.
///
/// This performs NO cryptography.
/// It checks:
/// - multikey encoding
/// - codec ↔ algorithm match
/// - key length
pub fn validate_verification_method_multikey(
    algorithm: Algorithm,
    binding_type: &str,
    public_key_multibase: &str,
) -> Result<(), AlgorithmError> {
    let parsed =
        parse_multikey(public_key_multibase).map_err(|_| AlgorithmError::InvalidKey(algorithm))?;

    // Validate that the declared binding label is compatible with the key algorithm.
    validate_key_binding(
        KeyBindingInput {
            binding_type,
            algorithm: Some(algorithm.as_str()),
        },
        &parsed,
    )
    .map_err(|_| AlgorithmError::InvalidKey(algorithm))?;

    // Enforce key length expectations
    let expected_len = match algorithm {
        Algorithm::Ed25519 => 32,
        Algorithm::X25519 => 32,
        Algorithm::P256 => 33,
        Algorithm::P384 => crypto_p384::P384_PUBLIC_KEY_COMPRESSED_LEN,
        Algorithm::P521 => crypto_p521::P521_PUBLIC_KEY_COMPRESSED_LEN,
        Algorithm::Secp256k1 => 33,
        Algorithm::MlDsa44 => 1312,
        Algorithm::MlDsa65 => 1952,
        Algorithm::MlDsa87 => 2592,
        Algorithm::MlKem512 => 800,
        Algorithm::MlKem768 => 1184,
        Algorithm::MlKem1024 => 1568,
        Algorithm::XWing768 => crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN,
        Algorithm::XWing1024 => crypto_x_wing::X_WING_1024_PUBLIC_KEY_LEN,
    };

    if parsed.public_key.len() != expected_len {
        return Err(AlgorithmError::InvalidKey(algorithm));
    }

    Ok(())
}
