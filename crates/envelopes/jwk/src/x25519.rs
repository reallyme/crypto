// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X25519 → JWK adapter
//!
//! Input:
//! - Raw 32-byte X25519 public key
//!
//! Output:
//! - RFC 8037 OKP JWK
//! - Compatible with JOSE, DID, and EUDI Wallets
//!
//! Example JWK:
//!
//! ```json
//! {
//!   "kty": "OKP",
//!   "crv": "X25519",
//!   "x": "<base64url>",
//!   "alg": "ECDH-ES",
//!   "use": "enc"
//! }
//! ```

use crate::{JwkOptions, JwtError};

use codec_base64url::bytes_to_base64url;
use codec_jcs::canonicalize_json;

use serde::Serialize;

/// RFC 8037 X25519 public JWK.
///
/// This encoder output is serialization-only. Parse untrusted JWK JSON through
/// [`crate::Jwk`], which rejects private-key members before constructing a key.
#[derive(Debug, Clone, Serialize)]
pub struct X25519Jwk {
    /// Key type. Always `OKP`.
    pub kty: &'static str,
    /// Curve name. Always `X25519`.
    pub crv: &'static str,
    /// Base64url-encoded raw X25519 public key.
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

/// Convert a raw 32-byte X25519 public key into a JWK.
pub fn x25519_public_key_to_jwk(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<X25519Jwk, JwtError> {
    if public_key.len() != 32 {
        return Err(JwtError::InvalidX25519Key);
    }

    let mut jwk = X25519Jwk {
        kty: "OKP",
        crv: "X25519",
        x: bytes_to_base64url(public_key),
        alg: None,
        use_: Some("enc".into()), // ← DEFAULT for X25519
        kid: options.kid,
    };

    if options.alg {
        jwk.alg = Some("ECDH-ES".into());
    }

    Ok(jwk)
}

/// Convert X25519 public key → **JCS-canonicalized JWK string** (RFC 8785).
pub fn x25519_public_key_to_jwk_jcs(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = x25519_public_key_to_jwk(public_key, options)?;

    let value = serde_json::to_value(&jwk).map_err(|_| JwtError::EncodingError)?;

    canonicalize_json(&value).map_err(|_| JwtError::EncodingError)
}
