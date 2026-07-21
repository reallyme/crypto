// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Validation and extraction of canonical public-key bytes from JWK values.

use codec_base64url::base64url_to_bytes;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_p256::decompress_public_key as decompress_p256_public_key;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_secp256k1::decompress_public_key as decompress_secp256k1_public_key;

use super::{AkpJwk, EcJwk, Jwk, OkpJwk};
use crate::JwtError;

const BASE64URL_LEN_32_BYTES: usize = 43;
const BASE64URL_LEN_ML_DSA_44_PUBLIC_KEY: usize = 1_750;
const BASE64URL_LEN_ML_DSA_65_PUBLIC_KEY: usize = 2_603;
const BASE64URL_LEN_ML_DSA_87_PUBLIC_KEY: usize = 3_456;
const BASE64URL_LEN_ML_KEM_512_PUBLIC_KEY: usize = 1_067;
const BASE64URL_LEN_ML_KEM_768_PUBLIC_KEY: usize = 1_579;
const BASE64URL_LEN_ML_KEM_1024_PUBLIC_KEY: usize = 2_091;
const BASE64URL_LEN_X_WING_768_PUBLIC_KEY: usize = 1_622;

/// Extract the canonical ReallyMe public-key bytes from a supported JWK.
pub fn public_key_bytes_from_jwk(jwk: &Jwk) -> Result<Vec<u8>, JwtError> {
    match jwk {
        Jwk::Okp(okp) => okp_public_key_bytes(okp),
        Jwk::Ec(ec) => ec_public_key_bytes(ec),
        Jwk::Akp(akp) => akp_public_key_bytes(akp),
    }
}

fn okp_public_key_bytes(okp: &OkpJwk) -> Result<Vec<u8>, JwtError> {
    if okp.kty != "OKP" {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    let (invalid_error, expected_alg, expected_use) = match okp.crv.as_str() {
        "Ed25519" => (JwtError::InvalidEd25519Key, "EdDSA", "sig"),
        "X25519" => (JwtError::InvalidX25519Key, "ECDH-ES", "enc"),
        _ => return Err(JwtError::UnsupportedKeyFormat),
    };
    if okp
        .alg
        .as_deref()
        .is_some_and(|value| value != expected_alg)
    {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    if okp
        .use_
        .as_deref()
        .is_some_and(|value| value != expected_use)
    {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    decode_fixed_public_key(&okp.x, BASE64URL_LEN_32_BYTES, 32, invalid_error)
}

fn ec_public_key_bytes(ec: &EcJwk) -> Result<Vec<u8>, JwtError> {
    if ec.kty != "EC" {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    let (invalid_error, alg) = match ec.crv.as_str() {
        "P-256" => (JwtError::InvalidP256Key, "ES256"),
        "secp256k1" => (JwtError::InvalidSecp256k1Key, "ES256K"),
        _ => return Err(JwtError::UnsupportedKeyFormat),
    };
    if ec.alg.as_deref().is_some_and(|value| value != alg) {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    let x = decode_fixed_public_key(&ec.x, BASE64URL_LEN_32_BYTES, 32, invalid_error)?;
    let y = decode_fixed_public_key(&ec.y, BASE64URL_LEN_32_BYTES, 32, invalid_error)?;
    let last_y = y.last().copied().ok_or(invalid_error)?;
    let prefix = if last_y & 1 == 0 { 0x02 } else { 0x03 };
    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(&x);

    #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
    {
        let _ = compressed;
        return Err(JwtError::UnsupportedKeyFormat);
    }

    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    {
        match ec.crv.as_str() {
            "P-256" => {
                let validated_sec1 =
                    decompress_p256_public_key(&compressed).map_err(|_| invalid_error)?;
                if validated_sec1.len() != 65
                    || validated_sec1.first().copied() != Some(0x04)
                    || validated_sec1.get(1..33) != Some(x.as_slice())
                    || validated_sec1.get(33..65) != Some(y.as_slice())
                {
                    return Err(invalid_error);
                }
            }
            "secp256k1" => {
                let (validated_x, validated_y) =
                    decompress_secp256k1_public_key(&compressed).map_err(|_| invalid_error)?;
                if validated_x != x || validated_y != y {
                    return Err(invalid_error);
                }
            }
            _ => return Err(JwtError::UnsupportedKeyFormat),
        };
        Ok(compressed)
    }
}

fn akp_public_key_bytes(akp: &AkpJwk) -> Result<Vec<u8>, JwtError> {
    if akp.kty != "AKP" {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    let (expected_encoded_len, expected_len, invalid_error) = match akp.alg.as_str() {
        "ML-DSA-44" => (
            BASE64URL_LEN_ML_DSA_44_PUBLIC_KEY,
            1312,
            JwtError::InvalidMlDsa44Key,
        ),
        "ML-DSA-65" => (
            BASE64URL_LEN_ML_DSA_65_PUBLIC_KEY,
            1952,
            JwtError::InvalidMlDsa65Key,
        ),
        "ML-DSA-87" => (
            BASE64URL_LEN_ML_DSA_87_PUBLIC_KEY,
            2592,
            JwtError::InvalidMlDsa87Key,
        ),
        "ML-KEM-512" => (
            BASE64URL_LEN_ML_KEM_512_PUBLIC_KEY,
            800,
            JwtError::InvalidMlKem512Key,
        ),
        "ML-KEM-768" => (
            BASE64URL_LEN_ML_KEM_768_PUBLIC_KEY,
            1184,
            JwtError::InvalidMlKem768Key,
        ),
        "ML-KEM-1024" => (
            BASE64URL_LEN_ML_KEM_1024_PUBLIC_KEY,
            1568,
            JwtError::InvalidMlKem1024Key,
        ),
        "SLH-DSA-SHA2-128s" => (
            BASE64URL_LEN_32_BYTES,
            32,
            JwtError::InvalidSlhDsaSha2128sKey,
        ),
        "X-Wing-768" => (
            BASE64URL_LEN_X_WING_768_PUBLIC_KEY,
            1216,
            JwtError::InvalidXWing768Key,
        ),
        _ => return Err(JwtError::UnsupportedKeyFormat),
    };
    decode_fixed_public_key(
        &akp.public_key,
        expected_encoded_len,
        expected_len,
        invalid_error,
    )
}

fn decode_fixed_public_key(
    encoded: &str,
    expected_encoded_len: usize,
    expected_decoded_len: usize,
    invalid_error: JwtError,
) -> Result<Vec<u8>, JwtError> {
    // Reject before decoding so an oversized public member cannot trigger a
    // second attacker-proportional allocation in the codec boundary.
    if encoded.len() != expected_encoded_len {
        return Err(invalid_error);
    }
    let public_key = base64url_to_bytes(encoded).map_err(|_| invalid_error)?;
    if public_key.len() != expected_decoded_len {
        return Err(invalid_error);
    }
    Ok(public_key)
}
