// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use envelopes_jwk::{
    ed25519_public_key_to_jwk, mldsa44_public_key_to_jwk, mldsa65_public_key_to_jwk,
    mldsa87_public_key_to_jwk, mlkem1024_public_key_to_jwk, mlkem512_public_key_to_jwk,
    mlkem768_public_key_to_jwk, x25519_public_key_to_jwk, Jwk, JwkOptions,
};
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use envelopes_jwk::{p256_public_key_to_jwk, secp256k1_public_key_to_jwk, JwtError};

use crate::error::JwkMultikeyError;
use codec_multikey::parse_multikey;

/// Converts a multikey string into the corresponding public JWK.
pub fn multikey_to_jwk(multikey: &str, options: JwkOptions) -> Result<Jwk, JwkMultikeyError> {
    let parsed = parse_multikey(multikey).map_err(|_| JwkMultikeyError::InvalidMultikey)?;

    let jwk = match parsed.algorithm_name() {
        "Ed25519" => {
            let j = ed25519_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Okp(j.into())
        }

        "X25519" => {
            let j = x25519_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Okp(j.into())
        }

        "P-256" | "ES256" => {
            #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
            {
                return Err(JwkMultikeyError::UnsupportedAlgorithm);
            }
            #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
            {
                let j = p256_public_key_to_jwk(parsed.public_key(), options)
                    .map_err(map_jwk_encoding_error)?;
                Jwk::Ec(j)
            }
        }

        "secp256k1" | "ES256K" => {
            #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
            {
                return Err(JwkMultikeyError::UnsupportedAlgorithm);
            }
            #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
            {
                let j = secp256k1_public_key_to_jwk(parsed.public_key(), options)
                    .map_err(map_jwk_encoding_error)?;
                Jwk::Ec(j)
            }
        }

        "ML-DSA-87" => {
            let j = mldsa87_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Akp(j.into())
        }

        "ML-DSA-44" => Jwk::Akp(
            mldsa44_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),
        "ML-DSA-65" => Jwk::Akp(
            mldsa65_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),

        "ML-KEM-1024" => {
            let j = mlkem1024_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Akp(j.into())
        }

        "ML-KEM-512" => Jwk::Akp(
            mlkem512_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),
        "ML-KEM-768" => Jwk::Akp(
            mlkem768_public_key_to_jwk(parsed.public_key(), options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),

        _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
    };

    Ok(jwk)
}

#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
fn map_jwk_encoding_error(error: JwtError) -> JwkMultikeyError {
    match error {
        JwtError::BackendUnavailable => JwkMultikeyError::UnsupportedAlgorithm,
        _ => JwkMultikeyError::EncodingError,
    }
}
