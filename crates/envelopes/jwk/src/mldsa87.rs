// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-87 → JWK adapter
//!
//! WARNING NON-STANDARD / BEST-EFFORT
//!
//! There is currently no RFC-standard JWK representation for
//! post-quantum signature schemes such as ML-DSA-87.
//!
//! This encoding follows the ReallyMe AKP convention and is intended for:
//! - DID documents
//! - Wallet key registries
//! - Cross-language interoperability (TS / Go / Swift / Rust)
//!
//! JWK shape:
//!
//! ```json
//! {
//!   "kty": "AKP",
//!   "pub": "<base64url>",
//!   "alg": "ML-DSA-87",
//!   "use": "sig"
//! }
//! ```

use crate::{JwkOptions, JwtError};

use codec_base64url::bytes_to_base64url;
use codec_jcs::canonicalize_json;

use serde::{Deserialize, Serialize};

/// Predicted / experimental JWK for ML-DSA-87
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlDsa87Jwk {
    /// Key type. Always `AKP`.
    pub kty: &'static str,
    /// Base64url-encoded raw ML-DSA-87 public key.
    #[serde(rename = "pub")]
    pub public_key: String,

    /// ReallyMe algorithm identifier. Always `ML-DSA-87`.
    pub alg: String,

    /// Optional JOSE public key use.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    /// Optional key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Convert a raw ML-DSA-87 public key (2592 bytes) into a JWK.
///
/// This is a **best-effort, non-standard** representation.
pub fn mldsa87_public_key_to_jwk(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<MlDsa87Jwk, JwtError> {
    if public_key.len() != 2592 {
        return Err(JwtError::InvalidMlDsa87Key);
    }

    let mut jwk = MlDsa87Jwk {
        kty: "AKP",
        public_key: bytes_to_base64url(public_key),
        alg: "ML-DSA-87".into(),
        use_: None,
        kid: options.kid,
    };

    if options.use_sig {
        jwk.use_ = Some("sig".into());
    }

    Ok(jwk)
}

/// Convert ML-DSA-87 public key → **JCS-canonicalized JWK string** (RFC 8785).
pub fn mldsa87_public_key_to_jwk_jcs(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = mldsa87_public_key_to_jwk(public_key, options)?;

    let value = serde_json::to_value(&jwk).map_err(|_| JwtError::EncodingError)?;

    canonicalize_json(&value).map_err(|_| JwtError::EncodingError)
}
