// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! P-256 → JWK adapter
//!
//! Input:
//! - 33-byte compressed SEC1 (0x02 / 0x03 + X)
//! - 65-byte uncompressed SEC1 (0x04 + X + Y)
//!
//! Output:
//! - RFC 7517 EC JWK (P-256)
//! - Compatible with WebCrypto, Go, Swift CryptoKit, EUDI Wallets

use crate::{EcJwk, JwkOptions, JwtError};

use codec_base64url::bytes_to_base64url;
use codec_jcs::canonicalize_json;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_p256::decompress_public_key;

/// Convert a SEC1 P-256 public key (compressed or uncompressed) into a JWK.
pub fn p256_public_key_to_jwk(
    public_key_sec1: &[u8],
    options: JwkOptions,
) -> Result<EcJwk, JwtError> {
    // Normalize to uncompressed SEC1
    let uncompressed = match public_key_sec1.len() {
        // compressed SEC1
        33 => {
            #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
            {
                decompress_public_key(public_key_sec1).map_err(|_| JwtError::InvalidP256Key)?
            }

            #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
            {
                return Err(JwtError::UnsupportedKeyFormat);
            }
        }

        // already uncompressed
        65 => public_key_sec1.to_vec(),

        _ => return Err(JwtError::InvalidP256Key),
    };

    // SEC1 uncompressed format: 0x04 || X || Y
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(JwtError::InvalidP256Key);
    }

    let x = &uncompressed[1..33];
    let y = &uncompressed[33..65];

    let mut jwk = EcJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: bytes_to_base64url(x),
        y: bytes_to_base64url(y),
        alg: None,
        use_: None,
        kid: options.kid,
    };

    if options.alg {
        jwk.alg = Some("ES256".into());
    }
    if options.use_sig {
        jwk.use_ = Some("sig".into());
    }

    Ok(jwk)
}

/// Convert P-256 public key → JCS-canonicalized JWK string (RFC 8785).
pub fn p256_public_key_to_jwk_jcs(
    public_key_sec1: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = p256_public_key_to_jwk(public_key_sec1, options)?;

    let value = serde_json::to_value(&jwk).map_err(|_| JwtError::EncodingError)?;

    canonicalize_json(&value).map_err(|_| JwtError::EncodingError)
}
