// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-1024 → JWK adapter
//!
//! WARNING NON-STANDARD / BEST-EFFORT
//!
//! There is currently no official JOSE / JWK definition for
//! post-quantum KEM keys such as ML-KEM-1024.
//!
//! This encoding follows the ReallyMe AKP convention
//! and is intended for:
//! - DID Documents
//! - Wallet key registries
//! - Key agreement metadata
//! - Cross-language interoperability (TS / Go / Swift / Rust)
//!
//! JWK shape:
//!
//! ```json
//! {
//!   "kty": "AKP",
//!   "pub": "<base64url>",
//!   "alg": "ML-KEM-1024",
//!   "use": "enc"
//! }
//! ```

use crate::{JwkOptions, JwtError};

use codec_base64url::bytes_to_base64url;
use codec_jcs::canonicalize_json;

use serde::{Deserialize, Serialize};

/// Predicted / experimental JWK for ML-KEM-1024
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlKem1024Jwk {
    /// Key type. Always `AKP`.
    pub kty: &'static str,
    /// Base64url-encoded raw ML-KEM-1024 public key.
    #[serde(rename = "pub")]
    pub public_key: String,

    /// ReallyMe algorithm identifier. Always `ML-KEM-1024`.
    pub alg: String,

    /// Optional JOSE public key use.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    /// Optional key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Convert a raw ML-KEM-1024 public key (1568 bytes) into a JWK.
///
/// This is a **best-effort, non-standard** representation.
pub fn mlkem1024_public_key_to_jwk(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<MlKem1024Jwk, JwtError> {
    if public_key.len() != 1568 {
        return Err(JwtError::InvalidMlKem1024Key);
    }

    let mut jwk = MlKem1024Jwk {
        kty: "AKP",
        public_key: bytes_to_base64url(public_key),
        alg: "ML-KEM-1024".into(),
        use_: None,
        kid: options.kid,
    };

    if options.use_enc {
        jwk.use_ = Some("enc".into());
    }

    Ok(jwk)
}

/// Convert ML-KEM-1024 public key → **JCS-canonicalized JWK string** (RFC 8785).
pub fn mlkem1024_public_key_to_jwk_jcs(
    public_key: &[u8],
    options: JwkOptions,
) -> Result<String, JwtError> {
    let jwk = mlkem1024_public_key_to_jwk(public_key, options)?;

    let value = serde_json::to_value(&jwk).map_err(|_| JwtError::EncodingError)?;

    canonicalize_json(&value).map_err(|_| JwtError::EncodingError)
}
