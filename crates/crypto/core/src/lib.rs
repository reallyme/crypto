// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared algorithm identities and schema-defined failures.
//!
//! Algorithm selectors have total checked protobuf bridges. Native failures
//! use the canonical schema reason without per-area diagnostic vocabularies.
//! This package contains no cryptographic implementations.

/// Algorithm identifier enums shared across the workspace.
pub mod algorithm;
/// Canonical schema-defined error types.
pub mod error;

/// Random output-purpose vocabulary shared with entropy providers.
pub mod random;

pub use algorithm::{AeadAlgorithm, Algorithm, HashAlgorithm, KeyWrapAlgorithm, MacAlgorithm};
/// Immutable primitive parameters and limits generated from the schema.
pub use crypto_proto::contract_constants;
pub use error::{CryptoError, CryptoErrorBranch, CryptoErrorReason};
pub use random::RngOutputKind;

/// Owner-local conversions from schema-defined algorithm identities.
#[cfg(feature = "protobuf")]
pub mod convert;
