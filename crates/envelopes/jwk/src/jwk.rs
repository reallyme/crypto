// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared JWK data structures.

use codec_base64url::base64url_to_bytes;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_p256::decompress_public_key as decompress_p256_public_key;
#[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
use crypto_secp256k1::decompress_public_key as decompress_secp256k1_public_key;
use serde::{Deserialize, Serialize};

use crate::JwtError;

/// Common optional JWK metadata controls.
#[derive(Debug, Clone, Default)]
pub struct JwkOptions {
    /// Include an `alg` member when the key's algorithm mapping is known.
    pub alg: bool,
    /// Include `use: "sig"` for signature keys.
    pub use_sig: bool,
    /// Include `use: "enc"` for key agreement or KEM keys.
    pub use_enc: bool,
    /// Optional key identifier copied into the JWK.
    pub kid: Option<String>,
}

/// Elliptic-curve JWK with affine coordinates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcJwk {
    /// Key type. Always `EC`.
    pub kty: String,
    /// JOSE curve name.
    pub crv: String,
    /// Base64url-encoded affine x coordinate.
    pub x: String,
    /// Base64url-encoded affine y coordinate.
    pub y: String,
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

/// OKP JWK over raw public key bytes for RFC 8037 Ed/X curves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkpJwk {
    /// Key type. Always `OKP`.
    pub kty: String,
    /// RFC 8037 curve name.
    pub crv: String,
    /// Base64url-encoded raw public key bytes.
    pub x: String,
    /// Optional JOSE or ReallyMe algorithm identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Optional JOSE public key use.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Optional key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Algorithm-bound asymmetric key-pair JWK over raw public key bytes.
///
/// Post-quantum JOSE key representations are not finalized. ReallyMe uses its
/// ratified AKP shape for PQ keys so DID/VC material does not overload RFC
/// 8037's `OKP` key type, which is reserved for Ed/X curves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkpJwk {
    /// Key type. Always `AKP`.
    pub kty: String,
    /// ReallyMe post-quantum algorithm identifier.
    pub alg: String,
    /// Base64url-encoded raw public key bytes.
    #[serde(rename = "pub")]
    pub public_key: String,
    /// Optional JOSE public key use.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Optional key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Unified JWK enum for code that accepts EC, OKP, and AKP keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Jwk {
    /// EC JWK variant.
    Ec(EcJwk),
    /// OKP JWK variant for Ed/X curves.
    Okp(OkpJwk),
    /// AKP JWK variant for post-quantum keys.
    Akp(AkpJwk),
}

/// JSON Web Key Set wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// Public keys in the set.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Create a JWKS from already-parsed public JWK values.
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    /// Consume the wrapper and return the keys.
    pub fn into_keys(self) -> Vec<Jwk> {
        self.keys
    }
}

impl Jwk {
    /// Extract the canonical ReallyMe public-key bytes from a supported JWK.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, JwtError> {
        public_key_bytes_from_jwk(self)
    }
}

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
    let (expected_len, invalid_error) = match okp.crv.as_str() {
        "Ed25519" => (32, JwtError::InvalidEd25519Key),
        "X25519" => (32, JwtError::InvalidX25519Key),
        _ => return Err(JwtError::UnsupportedKeyFormat),
    };
    let public_key = base64url_to_bytes(&okp.x).map_err(|_| invalid_error)?;
    if public_key.len() != expected_len {
        return Err(invalid_error);
    }
    Ok(public_key)
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
    let x = base64url_to_bytes(&ec.x).map_err(|_| invalid_error)?;
    let y = base64url_to_bytes(&ec.y).map_err(|_| invalid_error)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(invalid_error);
    }
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
                decompress_p256_public_key(&compressed).map_err(|_| invalid_error)?;
            }
            "secp256k1" => {
                decompress_secp256k1_public_key(&compressed).map_err(|_| invalid_error)?;
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
    let (expected_len, invalid_error) = match akp.alg.as_str() {
        "ML-DSA-44" => (1312, JwtError::InvalidMlDsa44Key),
        "ML-DSA-65" => (1952, JwtError::InvalidMlDsa65Key),
        "ML-DSA-87" => (2592, JwtError::InvalidMlDsa87Key),
        "ML-KEM-512" => (800, JwtError::InvalidMlKem512Key),
        "ML-KEM-768" => (1184, JwtError::InvalidMlKem768Key),
        "ML-KEM-1024" => (1568, JwtError::InvalidMlKem1024Key),
        "SLH-DSA-SHA2-128s" => (32, JwtError::InvalidSlhDsaSha2128sKey),
        "X-Wing-768" => (1216, JwtError::InvalidXWing768Key),
        "X-Wing-1024" => (1600, JwtError::InvalidXWing1024Key),
        _ => return Err(JwtError::UnsupportedKeyFormat),
    };
    let public_key = base64url_to_bytes(&akp.public_key).map_err(|_| invalid_error)?;
    if public_key.len() != expected_len {
        return Err(invalid_error);
    }
    Ok(public_key)
}

use crate::{ed25519::Ed25519Jwk, mldsa87::MlDsa87Jwk, mlkem1024::MlKem1024Jwk, x25519::X25519Jwk};

impl From<Ed25519Jwk> for OkpJwk {
    fn from(j: Ed25519Jwk) -> Self {
        OkpJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: j.x,
            alg: j.alg,
            use_: j.use_,
            kid: j.kid,
        }
    }
}

impl From<X25519Jwk> for OkpJwk {
    fn from(j: X25519Jwk) -> Self {
        OkpJwk {
            kty: "OKP".into(),
            crv: "X25519".into(),
            x: j.x,
            alg: j.alg,
            use_: j.use_,
            kid: j.kid,
        }
    }
}

impl From<MlDsa87Jwk> for AkpJwk {
    fn from(j: MlDsa87Jwk) -> Self {
        AkpJwk {
            kty: "AKP".into(),
            alg: j.alg,
            public_key: j.public_key,
            use_: j.use_,
            kid: j.kid,
        }
    }
}

impl From<MlKem1024Jwk> for AkpJwk {
    fn from(j: MlKem1024Jwk) -> Self {
        AkpJwk {
            kty: "AKP".into(),
            alg: j.alg,
            public_key: j.public_key,
            use_: j.use_,
            kid: j.kid,
        }
    }
}
