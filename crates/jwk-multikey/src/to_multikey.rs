// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use codec_multikey::encode_multikey;
use envelopes_jwk::Jwk;

use crate::JwkMultikeyError;

/// Convert a JWK → multikey string.
///
/// Guarantees byte-for-byte round-trip equivalence.
pub fn jwk_to_multikey(jwk: &Jwk) -> Result<String, JwkMultikeyError> {
    let codec_name = match jwk {
        Jwk::Okp(okp) => match okp.crv.as_str() {
            "Ed25519" => "ed25519-pub",
            "X25519" => "x25519-pub",
            _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
        },
        Jwk::Akp(akp) => match akp.alg.as_str() {
            "ML-DSA-44" => "mldsa-44-pub",
            "ML-DSA-65" => "mldsa-65-pub",
            "ML-DSA-87" => "mldsa-87-pub",
            "ML-KEM-512" => "mlkem-512-pub",
            "ML-KEM-768" => "mlkem-768-pub",
            "ML-KEM-1024" => "mlkem-1024-pub",
            _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
        },
        Jwk::Ec(ec) => match ec.crv.as_str() {
            "P-256" => "p256-pub",
            "secp256k1" => "secp256k1-pub",
            _ => return Err(JwkMultikeyError::UnsupportedAlgorithm),
        },
    };

    // The JWK crate owns key-shape, metadata, length, and exact-coordinate
    // validation. Reusing that boundary prevents this adapter from drifting
    // into a second envelope parser with weaker policy.
    let public_key = jwk
        .public_key_bytes()
        .map_err(|_| JwkMultikeyError::InvalidJwk)?;
    encode_multikey(codec_name, &public_key).map_err(|_| JwkMultikeyError::EncodingError)
}
