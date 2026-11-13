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
