// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadFailureKind {
    /// The supplied key material was not valid for the cipher.
    InvalidKeyMaterial,
    /// An input length exceeded the representable range.
    LengthOverflow,
    /// The ciphertext was shorter than the authentication tag.
    ShortCiphertext,
    /// The backend returned an output of unexpected length.
    InvalidOutputLength,
    /// Tag verification failed (ciphertext or AAD tampered/wrong key).
    AuthenticationFailed,
    /// The backend reported an unspecified internal failure.
    BackendFailure,
}

impl core::fmt::Display for AeadFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            AeadFailureKind::InvalidKeyMaterial => "invalid key material",
            AeadFailureKind::LengthOverflow => "length overflow",
            AeadFailureKind::ShortCiphertext => "ciphertext shorter than tag",
            AeadFailureKind::InvalidOutputLength => "backend returned invalid output length",
            AeadFailureKind::AuthenticationFailed => "authentication failed",
            AeadFailureKind::BackendFailure => "backend failure",
        };
        write!(f, "{detail}")
    }
}
