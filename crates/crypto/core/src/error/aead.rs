// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Backend implementation that performed an AEAD operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadBackend {
    /// Pure-Rust native backend.
    Native,
    /// Swift/Apple platform backend.
    Swift,
    /// WebAssembly backend.
    Wasm,
    /// Kotlin/Android platform backend.
    Kotlin,
}

impl core::fmt::Display for AeadBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            AeadBackend::Native => "native",
            AeadBackend::Swift => "swift",
            AeadBackend::Wasm => "wasm",
            AeadBackend::Kotlin => "kotlin",
        };
        write!(f, "{name}")
    }
}

/// Specific reason an AEAD encrypt or decrypt operation failed.
pub type AeadFailureKind = super::CryptoError;
