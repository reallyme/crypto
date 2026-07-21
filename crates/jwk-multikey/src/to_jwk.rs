// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use envelopes_jwk::{
    ed25519_public_key_to_jwk, mldsa44_public_key_to_jwk, mldsa65_public_key_to_jwk,
    mldsa87_public_key_to_jwk, mlkem1024_public_key_to_jwk, mlkem512_public_key_to_jwk,
    mlkem768_public_key_to_jwk, p256_public_key_to_jwk, secp256k1_public_key_to_jwk,
    x25519_public_key_to_jwk, Jwk, JwkOptions,
};

use crate::error::JwkMultikeyError;
use codec_multikey::parse_multikey;

/// Converts a multikey string into the corresponding public JWK.
pub fn multikey_to_jwk(multikey: &str, options: JwkOptions) -> Result<Jwk, JwkMultikeyError> {
    let parsed = parse_multikey(multikey).map_err(|_| JwkMultikeyError::InvalidMultikey)?;

    let jwk = match parsed.alg {
        "Ed25519" => {
            let j = ed25519_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Okp(j.into())
        }

        "X25519" => {
            let j = x25519_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Okp(j.into())
        }

        "P-256" | "ES256" => {
            let j = p256_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Ec(j)
        }

        "secp256k1" | "ES256K" => {
            let j = secp256k1_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Ec(j)
        }

        "ML-DSA-87" => {
            let j = mldsa87_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Akp(j.into())
        }

        "ML-DSA-44" => Jwk::Akp(
            mldsa44_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),
        "ML-DSA-65" => Jwk::Akp(
            mldsa65_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),

        "ML-KEM-1024" => {
            let j = mlkem1024_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?;
            Jwk::Akp(j.into())
        }

        "ML-KEM-512" => Jwk::Akp(
            mlkem512_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),
        "ML-KEM-768" => Jwk::Akp(
            mlkem768_public_key_to_jwk(&parsed.public_key, options)
                .map_err(|_| JwkMultikeyError::EncodingError)?,
        ),

        _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
    };

    Ok(jwk)
}
