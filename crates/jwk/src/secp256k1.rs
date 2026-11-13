// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! secp256k1 → JWK adapter
//!
//! Input: 33-byte compressed SEC1 public key
//! Output: EC JWK (secp256k1)

use crate::{EcJwk, JwkOptions, JwtError};

use crate::canonicalize_jwk::canonicalize_jwk;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use codec_base64url::bytes_to_base64url;

#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_secp256k1::decompress_public_key;

/// Convert a compressed SEC1 secp256k1 public key into a JWK.
///
/// - Input MUST be 33 bytes (0x02/0x03 + X)
/// - Output is RFC-compliant EC JWK
pub fn secp256k1_public_key_to_jwk(
    compressed_sec1: &[u8],
    options: JwkOptions,
) -> Result<EcJwk, JwtError> {
    if compressed_sec1.len() != 33 {
        return Err(JwtError::PRIMITIVE_INVALID_PUBLIC_KEY);
    }

    #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
    {
        let _ = options;
        return Err(JwtError::PROVIDER_UNSUPPORTED_BACKEND);
    }

    #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
    {
        let (x, y) =
            decompress_public_key(compressed_sec1).map_err(crate::error::public_key_error)?;

        let mut jwk = EcJwk {
            kty: "EC".to_string(),
            crv: "secp256k1".to_string(),
            x: bytes_to_base64url(&x),
            y: bytes_to_base64url(&y),
            alg: None,
            use_: None,
            kid: options.kid,
        };

        if options.alg {
            jwk.alg = Some("ES256K".into());
        }
        if options.use_sig {
            jwk.use_ = Some("sig".into());
        }

        Ok(jwk)
    }
}

/// Convert secp256k1 public key → **JCS-canonicalized JWK string**
pub fn secp256k1_public_key_to_jwk_jcs(
    compressed_sec1: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = secp256k1_public_key_to_jwk(compressed_sec1, options)?;

    canonicalize_jwk(&jwk)
}
