// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ECDSA with explicit hash, input semantics and encoding.
//!
//! Certificate callers supply exact validated TBS bytes and select the hash
//! from the signature OID. Curve selection never implies a hash. Protocol
//! restrictions on curve/hash combinations belong to the calling protocol.
//! Verification accepts mathematically valid high-S signatures; low-S
//! canonicalization remains an explicit policy in the existing P-256 APIs.

#[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
mod brainpool;
mod constants;
mod digest;
mod encode;
#[cfg(feature = "operation-response")]
mod identity;
mod key;
#[cfg(all(
    feature = "brainpool",
    not(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))
))]
mod portable_brainpool;
mod sign;
mod verify;

use thiserror::Error;

pub use encode::{der_to_fixed, fixed_to_der};
pub use key::EcdsaKey;
pub use sign::{sign_with_provider, OpaqueEcdsaSigner};
pub use verify::{validate_public_key, verify};

/// Named curves. Unsupported curves return `UnsupportedCurve`; enum presence
/// alone does not mean that an implementation is available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521 (66-byte scalars).
    P521,
    /// brainpoolP256r1; requires `brainpool` or the native `brainpool-openssl` feature.
    BrainpoolP256r1,
    /// brainpoolP320r1; requires `brainpool` or the native `brainpool-openssl` feature.
    BrainpoolP320r1,
    /// brainpoolP384r1; requires `brainpool` or the native `brainpool-openssl` feature.
    BrainpoolP384r1,
    /// brainpoolP512r1; requires `brainpool` or the native `brainpool-openssl` feature.
    BrainpoolP512r1,
}

/// Explicit ECDSA hash, selected from validated signature parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaHash {
    /// SHA-256, including ecdsa-with-SHA256 OID 1.2.840.10045.4.3.2.
    Sha256,
    /// SHA-384, including ecdsa-with-SHA384 OID 1.2.840.10045.4.3.3.
    Sha384,
    /// SHA-512, including ecdsa-with-SHA512 OID 1.2.840.10045.4.3.4.
    Sha512,
}

/// Explicit message/prehash boundary; an already hashed input is never hashed
/// again. Prehash lengths must match the selected hash exactly.
#[derive(Clone, Copy)]
pub enum EcdsaInput<'a> {
    /// Exact message bytes; this operation hashes them once.
    Message {
        /// Hash selected by the caller.
        hash: EcdsaHash,
        /// Exact message bytes, such as DER TBSCertificate/TBSCertList.
        bytes: &'a [u8],
    },
    /// A caller-computed digest, consumed without additional hashing.
    Prehash {
        /// Hash used to compute the digest.
        hash: EcdsaHash,
        /// Digest bytes of the selected hash's exact output length.
        bytes: &'a [u8],
    },
}

/// Signature encoding is always explicit; no length-based format guessing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaEncoding {
    /// Strict DER ECDSA-Sig-Value.
    Der,
    /// Fixed-width big-endian `r || s`, 64/96/132 bytes for P-256/384/521.
    FixedWidth,
}

/// Deterministic, secret-free ECDSA failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum EcdsaError {
    /// No reviewed implementation is exposed for this curve.
    #[error("unsupported ECDSA curve")]
    UnsupportedCurve,
    /// The linked native provider is outside the reviewed release policy.
    #[error("unsupported native ECDSA provider")]
    UnsupportedProvider,
    /// Invalid private scalar encoding or range.
    #[error("invalid ECDSA private key")]
    InvalidPrivateKey,
    /// Invalid SEC1 encoding, point at infinity, or off-curve point.
    #[error("invalid ECDSA public key")]
    InvalidPublicKey,
    /// Invalid signature encoding, scalars or mathematical verification.
    #[error("invalid ECDSA signature")]
    InvalidSignature,
    /// Digest length does not match its explicit hash.
    #[error("invalid ECDSA prehash length")]
    InvalidPrehashLength,
    /// Protected storage could not be allocated.
    #[error("ECDSA allocation failed")]
    AllocationFailed,
    /// The entropy provider failed or could not produce a valid scalar.
    #[error("ECDSA randomness unavailable")]
    RandomnessUnavailable,
    /// An opaque provider or signing backend failed.
    #[error("ECDSA provider failed")]
    ProviderFailed,
}

impl EcdsaCurve {
    pub(super) fn scalar_len(self) -> Result<usize, EcdsaError> {
        #[cfg(all(feature = "brainpool-openssl", not(target_arch = "wasm32")))]
        if matches!(
            self,
            Self::BrainpoolP256r1
                | Self::BrainpoolP320r1
                | Self::BrainpoolP384r1
                | Self::BrainpoolP512r1
        ) && !crate::native_provider::is_available()
        {
            return Err(EcdsaError::UnsupportedProvider);
        }
        match self {
            Self::P256 => Ok(constants::P256_SCALAR_LEN),
            Self::P384 => Ok(constants::P384_SCALAR_LEN),
            Self::P521 => Ok(constants::P521_SCALAR_LEN),
            #[cfg(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            ))]
            Self::BrainpoolP256r1 => Ok(constants::BRAINPOOL_P256_SCALAR_LEN),
            #[cfg(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            ))]
            Self::BrainpoolP320r1 => Ok(constants::BRAINPOOL_P320_SCALAR_LEN),
            #[cfg(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            ))]
            Self::BrainpoolP384r1 => Ok(constants::BRAINPOOL_P384_SCALAR_LEN),
            #[cfg(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            ))]
            Self::BrainpoolP512r1 => Ok(constants::BRAINPOOL_P512_SCALAR_LEN),
            #[cfg(not(any(
                feature = "brainpool",
                all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
            )))]
            _ => Err(EcdsaError::UnsupportedCurve),
        }
    }
}
