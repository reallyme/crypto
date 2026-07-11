// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 → JWK adapter
//!
//! Input:
//! - Raw 32-byte Ed25519 public key
//!
//! Output:
//! - RFC 7517 / 8037 OKP JWK
//! - Compatible with WebCrypto, JOSE, DID, and EUDI Wallets

use crate::{JwkOptions, JwtError};

use codec_base64url::bytes_to_base64url;
use codec_jcs::canonicalize_json;

use serde::{Deserialize, Serialize};

/// RFC 8037 Ed25519 JWK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Jwk {
    /// Key type. Always `OKP`.
    pub kty: &'static str,
    /// Curve name. Always `Ed25519`.
    pub crv: &'static str,
    /// Base64url-encoded raw Ed25519 public key.
    pub x: String,

    /// Optional JOSE algorithm identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Optional JOSE public key use.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    /// Optional key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Convert a raw 32-byte Ed25519 public key into a JWK.
pub fn ed25519_public_key_to_jwk(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<Ed25519Jwk, JwtError> {
    if public_key.len() != 32 {
        return Err(JwtError::InvalidEd25519Key);
    }

    let mut jwk = Ed25519Jwk {
        kty: "OKP",
        crv: "Ed25519",
        x: bytes_to_base64url(public_key),
        alg: None,
        use_: None,
        kid: options.kid,
    };

    if options.alg {
        jwk.alg = Some("EdDSA".into());
    }

    if options.use_sig {
        jwk.use_ = Some("sig".into());
    }

    Ok(jwk)
}

/// Convert Ed25519 public key → JCS-canonicalized JWK string (RFC 8785).
pub fn ed25519_public_key_to_jwk_jcs(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = ed25519_public_key_to_jwk(public_key, options)?;

    let value = serde_json::to_value(&jwk).map_err(|_| JwtError::EncodingError)?;

    canonicalize_json(&value).map_err(|_| JwtError::EncodingError)
}
