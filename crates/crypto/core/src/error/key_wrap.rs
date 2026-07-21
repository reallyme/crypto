// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Key-wrapping algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapAlgorithm {
    /// AES-128 Key Wrap as specified by RFC 3394 / NIST SP 800-38F.
    Aes128Kw,
    /// AES-192 Key Wrap as specified by RFC 3394 / NIST SP 800-38F.
    Aes192Kw,
    /// AES-256 Key Wrap as specified by RFC 3394 / NIST SP 800-38F.
    Aes256Kw,
}

impl core::fmt::Display for KeyWrapAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KeyWrapAlgorithm::Aes128Kw => "AES-128-KW",
            KeyWrapAlgorithm::Aes192Kw => "AES-192-KW",
            KeyWrapAlgorithm::Aes256Kw => "AES-256-KW",
        };
        write!(f, "{detail}")
    }
}

/// Key-wrap operation being attempted when a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapOperation {
    /// Wrapping plaintext key material.
    Wrap,
    /// Unwrapping wrapped key material.
    Unwrap,
}

impl core::fmt::Display for KeyWrapOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let op = match self {
            KeyWrapOperation::Wrap => "wrap",
            KeyWrapOperation::Unwrap => "unwrap",
        };
        write!(f, "{op}")
    }
}

/// Specific reason a key-wrap operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapFailureKind {
    /// The key-encryption key did not have the required length.
    InvalidKekLength,
    /// Plaintext key material was too short for RFC 3394 AES-KW.
    InvalidPlaintextLength,
    /// Wrapped key material was too short or malformed for RFC 3394 AES-KW.
    InvalidWrappedLength,
    /// An input or output length exceeded the representable range.
    LengthOverflow,
    /// The wrapped key integrity check failed.
    IntegrityCheckFailed,
    /// The backend reported an unspecified internal failure.
    BackendFailure,
}

impl core::fmt::Display for KeyWrapFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KeyWrapFailureKind::InvalidKekLength => "invalid key-encryption key length",
            KeyWrapFailureKind::InvalidPlaintextLength => "invalid plaintext key length",
            KeyWrapFailureKind::InvalidWrappedLength => "invalid wrapped key length",
            KeyWrapFailureKind::LengthOverflow => "length overflow",
            KeyWrapFailureKind::IntegrityCheckFailed => "integrity check failed",
            KeyWrapFailureKind::BackendFailure => "backend failure",
        };
        write!(f, "{detail}")
    }
}
