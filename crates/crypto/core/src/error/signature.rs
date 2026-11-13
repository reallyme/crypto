// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Backend implementation that performed a signature operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureBackend {
    /// Pure-Rust native backend.
    Native,
    /// Swift/Apple platform backend.
    Swift,
    /// WebAssembly backend.
    Wasm,
    /// Kotlin/Android platform backend.
    Kotlin,
    /// Apple Secure Enclave hardware-backed backend.
    SecureEnclave,
}

impl core::fmt::Display for SignatureBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            SignatureBackend::Native => "native",
            SignatureBackend::Swift => "swift",
            SignatureBackend::Wasm => "wasm",
            SignatureBackend::Kotlin => "kotlin",
            SignatureBackend::SecureEnclave => "secure_enclave",
        };
        write!(f, "{name}")
    }
}

/// Signature-related operation being attempted when a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureOperation {
    /// Producing a signature over a message.
    Sign,
    /// Verifying a signature against a message.
    Verify,
    /// Key generation, import, or other key management.
    KeyManagement,
}

impl core::fmt::Display for SignatureOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let op = match self {
            SignatureOperation::Sign => "sign",
            SignatureOperation::Verify => "verify",
            SignatureOperation::KeyManagement => "key_management",
        };
        write!(f, "{op}")
    }
}

/// Specific reason a signature operation failed.
pub type SignatureFailureKind = super::CryptoError;

/// Specific reason a key agreement operation failed.
pub type KeyAgreementFailureKind = super::CryptoError;

/// Specific reason a KEM (key encapsulation) operation failed.
pub type KemFailureKind = super::CryptoError;
