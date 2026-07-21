// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Hash function underlying an HMAC operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacHash {
    /// HMAC using SHA-256.
    Sha2_256,
    /// HMAC using SHA-384.
    Sha2_384,
    /// HMAC using SHA-512.
    Sha2_512,
}

impl core::fmt::Display for MacHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            MacHash::Sha2_256 => "SHA-256",
            MacHash::Sha2_384 => "SHA-384",
            MacHash::Sha2_512 => "SHA-512",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason an HMAC operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacFailureKind {
    /// The supplied key was empty or exceeded the accepted size limit.
    InvalidKeyLength,
    /// The supplied authentication tag length did not match the algorithm.
    InvalidTagLength,
    /// Tag verification failed.
    VerificationFailed,
    /// The backend reported an unspecified internal failure.
    BackendFailure,
}

impl core::fmt::Display for MacFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            MacFailureKind::InvalidKeyLength => "invalid key length",
            MacFailureKind::InvalidTagLength => "invalid tag length",
            MacFailureKind::VerificationFailed => "verification failed",
            MacFailureKind::BackendFailure => "backend failure",
        };
        write!(f, "{detail}")
    }
}
