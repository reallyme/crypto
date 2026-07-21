// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic operation-layer conventions.
//!
//! This module is deliberately free of generated protobuf, FFI, JNI, WASM,
//! Swift, Kotlin, Android, and TypeScript adapter code. Each operation family
//! is the semantic owner for every public route that exposes it.

pub mod aead;
#[cfg(feature = "constant-time")]
pub mod constant_time;
mod error;
mod family;
pub mod hash;
#[cfg(feature = "hpke-api")]
pub mod hpke;
#[cfg(any(
    feature = "argon2id",
    feature = "concat-kdf",
    feature = "hkdf",
    feature = "kmac",
    feature = "pbkdf2"
))]
pub mod kdf;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
pub mod kem;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
pub mod key_agreement;
#[cfg(any(
    feature = "ed25519",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "secp256k1",
    feature = "x25519",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024",
    feature = "slh-dsa",
    feature = "x-wing"
))]
pub mod key_encoding;
#[cfg(feature = "aes-kw")]
pub mod key_wrap;
pub mod mac;
/// Platform-key operation vocabulary and security classification.
pub mod platform_key;
#[cfg(feature = "csprng")]
pub mod random;
#[cfg(any(
    feature = "rsa",
    all(
        feature = "dispatch",
        any(
            feature = "ed25519",
            feature = "p256",
            feature = "p384",
            feature = "p521",
            feature = "secp256k1",
            feature = "ml-dsa-44",
            feature = "ml-dsa-65",
            feature = "ml-dsa-87",
            feature = "slh-dsa"
        )
    )
))]
pub mod signature;

pub use self::error::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
pub use self::family::OperationFamily;

/// Standard typed result returned by semantic operation implementations.
pub type OperationOutcome<R> = Result<R, OperationError>;
