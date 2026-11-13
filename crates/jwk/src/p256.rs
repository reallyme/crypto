// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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

use crate::canonicalize_jwk::canonicalize_jwk;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use codec_base64url::bytes_to_base64url;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_p256::compress_public_key;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_p256::decompress_public_key;

/// Convert a SEC1 P-256 public key (compressed or uncompressed) into a JWK.
pub fn p256_public_key_to_jwk(
    public_key_sec1: &[u8],
    options: JwkOptions,
) -> Result<EcJwk, JwtError> {
    #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
    return {
        let _ = (public_key_sec1, options);
        Err(JwtError::PROVIDER_UNSUPPORTED_BACKEND)
    };

    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    {
        // Normalize to uncompressed SEC1
        let uncompressed = match public_key_sec1.len() {
            // compressed SEC1
            33 => {
                #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
                {
                    decompress_public_key(public_key_sec1)
                        .map_err(crate::error::public_key_error)?
                }
            }

            // already uncompressed
            65 => {
                #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
                {
                    compress_public_key(public_key_sec1).map_err(crate::error::public_key_error)?;
                    public_key_sec1.to_vec()
                }
            }

            _ => return Err(JwtError::PRIMITIVE_INVALID_PUBLIC_KEY),
        };

        // SEC1 uncompressed format: 0x04 || X || Y
        if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
            return Err(JwtError::PRIMITIVE_INVALID_PUBLIC_KEY);
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
}

/// Convert P-256 public key → JCS-canonicalized JWK string (RFC 8785).
pub fn p256_public_key_to_jwk_jcs(
    public_key_sec1: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = p256_public_key_to_jwk(public_key_sec1, options)?;

    canonicalize_jwk(&jwk)
}
