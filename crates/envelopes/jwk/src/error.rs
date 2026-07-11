// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Typed errors for JWK encoding.

use thiserror::Error;

/// Errors returned while encoding public keys as JWKs.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum JwtError {
    /// The ML-DSA-44 public key length is invalid.
    #[error("invalid ML-DSA-44 public key")]
    InvalidMlDsa44Key,
    /// The ML-DSA-65 public key length is invalid.
    #[error("invalid ML-DSA-65 public key")]
    InvalidMlDsa65Key,
    /// The P-256 public key is malformed or has an invalid length.
    #[error("invalid P-256 public key")]
    InvalidP256Key,

    /// The secp256k1 public key is malformed or has an invalid length.
    #[error("invalid secp256k1 public key")]
    InvalidSecp256k1Key,

    /// The Ed25519 public key length is invalid.
    #[error("invalid Ed25519 public key")]
    InvalidEd25519Key,

    /// The X25519 public key length is invalid.
    #[error("invalid X25519 public key")]
    InvalidX25519Key,

    /// The ML-DSA-87 public key length is invalid.
    #[error("invalid ML-DSA-87 public key")]
    InvalidMlDsa87Key,

    /// The ML-KEM-512 public key length is invalid.
    #[error("invalid ML-KEM-512 public key")]
    InvalidMlKem512Key,
    /// The ML-KEM-768 public key length is invalid.
    #[error("invalid ML-KEM-768 public key")]
    InvalidMlKem768Key,

    /// The ML-KEM-1024 public key length is invalid.
    #[error("invalid ML-KEM-1024 public key")]
    InvalidMlKem1024Key,

    /// The SLH-DSA-SHA2-128s public key length is invalid.
    #[error("invalid SLH-DSA-SHA2-128s public key")]
    InvalidSlhDsaSha2128sKey,

    /// The X-Wing-768 public key length is invalid.
    #[error("invalid X-Wing-768 public key")]
    InvalidXWing768Key,

    /// The X-Wing-1024 public key length is invalid.
    #[error("invalid X-Wing-1024 public key")]
    InvalidXWing1024Key,

    /// The requested key format is not supported.
    #[error("unsupported key format")]
    UnsupportedKeyFormat,

    /// JSON or canonicalization failed.
    #[error("encoding error")]
    EncodingError,
}
