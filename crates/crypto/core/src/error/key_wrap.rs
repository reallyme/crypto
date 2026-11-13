// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
pub type KeyWrapFailureKind = super::CryptoError;
