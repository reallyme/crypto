// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_base64url::base64url_to_bytes;
use codec_multikey::encode_multikey;
use envelopes_jwk::{AkpJwk, EcJwk, Jwk, OkpJwk};

use crate::JwkMultikeyError;

/// Convert a JWK → multikey string.
///
/// Guarantees byte-for-byte round-trip equivalence.
pub fn jwk_to_multikey(jwk: &Jwk) -> Result<String, JwkMultikeyError> {
    match jwk {
        Jwk::Okp(okp) => okp_to_multikey(okp),
        Jwk::Akp(akp) => akp_to_multikey(akp),
        Jwk::Ec(ec) => ec_to_multikey(ec),
    }
}

/// OKP JWK → multikey (pure encoding)
fn okp_to_multikey(jwk: &OkpJwk) -> Result<String, JwkMultikeyError> {
    let public_key = base64url_to_bytes(&jwk.x).map_err(|_| JwkMultikeyError::EncodingError)?;

    let codec_name = match jwk.crv.as_str() {
        "Ed25519" => "ed25519-pub",
        "X25519" => "x25519-pub",
        _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
    };

    encode_multikey(codec_name, &public_key).map_err(|_| JwkMultikeyError::EncodingError)
}

/// AKP JWK → multikey for post-quantum public keys with assigned multicodecs.
fn akp_to_multikey(jwk: &AkpJwk) -> Result<String, JwkMultikeyError> {
    let public_key =
        base64url_to_bytes(&jwk.public_key).map_err(|_| JwkMultikeyError::EncodingError)?;

    let codec_name = match jwk.alg.as_str() {
        "ML-DSA-87" => "mldsa-87-pub",
        "ML-DSA-44" => "mldsa-44-pub",
        "ML-DSA-65" => "mldsa-65-pub",
        "ML-KEM-1024" => "mlkem-1024-pub",
        "ML-KEM-512" => "mlkem-512-pub",
        "ML-KEM-768" => "mlkem-768-pub",
        _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
    };

    encode_multikey(codec_name, &public_key).map_err(|_| JwkMultikeyError::EncodingError)
}

/// EC JWK → multikey
///
/// Rebuilds uncompressed SEC1 → compresses deterministically → multicodec
fn ec_to_multikey(jwk: &EcJwk) -> Result<String, JwkMultikeyError> {
    let x = base64url_to_bytes(&jwk.x).map_err(|_| JwkMultikeyError::EncodingError)?;
    let y = base64url_to_bytes(&jwk.y).map_err(|_| JwkMultikeyError::EncodingError)?;

    if x.len() != 32 || y.len() != 32 {
        return Err(JwkMultikeyError::InvalidJwk);
    }

    // 0x04 || X || Y (SEC1 uncompressed)
    let coordinate_length = x
        .len()
        .checked_add(y.len())
        .ok_or(JwkMultikeyError::EncodingError)?;
    let sec1_length = coordinate_length
        .checked_add(1)
        .ok_or(JwkMultikeyError::EncodingError)?;
    let mut sec1 = Vec::with_capacity(sec1_length);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    match jwk.crv.as_str() {
        "secp256k1" => compress_secp256k1(&sec1),
        "P-256" => compress_p256(&sec1),
        _ => Err(JwkMultikeyError::UnsupportedAlgorithm),
    }
}

/// Deterministic secp256k1 compression
fn compress_secp256k1(sec1: &[u8]) -> Result<String, JwkMultikeyError> {
    let x = sec1.get(1..33).ok_or(JwkMultikeyError::InvalidJwk)?;
    let y = sec1.get(33..65).ok_or(JwkMultikeyError::InvalidJwk)?;
    let y_last = y.last().ok_or(JwkMultikeyError::InvalidJwk)?;

    let mut compressed = [0_u8; 33];
    compressed[0] = if y_last & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..].copy_from_slice(x);

    // Re-decompression through the primitive validates that the supplied JWK
    // coordinates represent the same point instead of accepting arbitrary bytes.
    let (validated_x, validated_y) = crypto_secp256k1::decompress_public_key(&compressed)
        .map_err(|_| JwkMultikeyError::InvalidJwk)?;
    if validated_x != x || validated_y != y {
        return Err(JwkMultikeyError::InvalidJwk);
    }

    encode_multikey("secp256k1-pub", &compressed).map_err(|_| JwkMultikeyError::EncodingError)
}

/// Deterministic P-256 compression
fn compress_p256(sec1: &[u8]) -> Result<String, JwkMultikeyError> {
    let compressed = crypto_p256::compress_p256(sec1).map_err(|_| JwkMultikeyError::InvalidJwk)?;
    encode_multikey("p256-pub", &compressed).map_err(|_| JwkMultikeyError::EncodingError)
}
