// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared vocabulary types for the ReallyMe crypto workspace.
//!
//! This crate defines the algorithm identifiers ([`Algorithm`],
//! [`AeadAlgorithm`], [`HashAlgorithm`]) and the typed error taxonomy
//! ([`CryptoError`] and its failure-kind enums) that
//! every primitive, the dispatch layer, and the FFI boundary share. It
//! contains no cryptographic behavior — only the definitions the rest of
//! the workspace agrees on — so that errors carry fixed, secret-free
//! descriptors and algorithm selection is a single closed enum rather than
//! stringly-typed.

/// Algorithm identifier enums shared across the workspace.
pub mod algorithm;
/// Typed error taxonomy and failure-kind enums.
pub mod error;

pub use algorithm::{AeadAlgorithm, Algorithm, HashAlgorithm, MacAlgorithm};
pub use error::{
    AeadBackend, AeadFailureKind, ConstantTimeFailureKind, CryptoError, HkdfFailureKind, HkdfHash,
    KdfAlgorithm, KdfFailureKind, KdfProfile, KemFailureKind, KeyAgreementFailureKind,
    KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation, MacFailureKind, MacHash,
    RngFailureKind, RngOutputKind, SignatureBackend, SignatureFailureKind, SignatureOperation,
};
