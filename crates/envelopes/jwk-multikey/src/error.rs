// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Typed errors for JWK and multikey conversion.

use thiserror::Error;

/// Errors returned while converting between JWK and multikey encodings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwkMultikeyError {
    /// The multikey string could not be parsed.
    #[error("invalid multikey")]
    InvalidMultikey,

    /// The JWK or multikey algorithm is not supported.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The JWK shape or key coordinates are invalid.
    #[error("invalid JWK")]
    InvalidJwk,

    /// Encoding failed after validation.
    #[error("encoding error")]
    EncodingError,
}
