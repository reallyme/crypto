// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::AlgorithmError;
use codec_multikey::{parse_multikey, validate_key_binding, KeyBindingInput};
use crypto_core::Algorithm;

const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;

fn expected_public_key_len(algorithm: Algorithm) -> Result<usize, AlgorithmError> {
    match algorithm {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                Ok(32)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                Ok(32)
            }
            #[cfg(not(feature = "x25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                Ok(33)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                Ok(crypto_p384::P384_PUBLIC_KEY_COMPRESSED_LEN)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                Ok(crypto_p521::P521_PUBLIC_KEY_COMPRESSED_LEN)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                Ok(33)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                Ok(1312)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                Ok(1952)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                Ok(2592)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::SlhDsaSha2_128s => Ok(SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN),
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                Ok(800)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                Ok(1184)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                Ok(1568)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                Ok(crypto_x_wing::X_WING_768_PUBLIC_KEY_LEN)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
    }
}

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
    // Check the compiled policy first so disabled algorithms return a stable
    // unsupported error instead of leaking parser-specific validation details.
    let expected_len = expected_public_key_len(algorithm)?;

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

    if parsed.public_key.len() != expected_len {
        return Err(AlgorithmError::InvalidKey(algorithm));
    }

    Ok(())
}
