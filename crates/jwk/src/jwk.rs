// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared JWK data structures.

use serde::{Deserialize, Serialize, Serializer};

use crate::JwtError;

mod deserialize;
mod public_key;

pub use public_key::public_key_bytes_from_jwk;

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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone)]
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

impl Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Ec(jwk) => jwk.serialize(serializer),
            Self::Okp(jwk) => jwk.serialize(serializer),
            Self::Akp(jwk) => jwk.serialize(serializer),
        }
    }
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
