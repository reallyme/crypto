// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureFailureKind {
    /// The backend reported an unspecified internal failure.
    BackendFailure,
    /// The supplied private key was malformed or invalid.
    InvalidPrivateKey,
    /// The supplied public key was malformed or invalid.
    InvalidPublicKey,
    /// The signature was malformed or failed verification.
    InvalidSignature,
    /// The message input was invalid for the operation.
    InvalidMessage,
    /// Key generation did not succeed.
    KeyGenerationFailed,
    /// The Secure Enclave was not available on this device.
    SecureEnclaveUnavailable,
    /// The Secure Enclave rejected the supplied key.
    SecureEnclaveRejectedKey,
}

impl core::fmt::Display for SignatureFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            SignatureFailureKind::BackendFailure => "backend failure",
            SignatureFailureKind::InvalidPrivateKey => "invalid private key",
            SignatureFailureKind::InvalidPublicKey => "invalid public key",
            SignatureFailureKind::InvalidSignature => "invalid signature",
            SignatureFailureKind::InvalidMessage => "invalid message",
            SignatureFailureKind::KeyGenerationFailed => "key generation failed",
            SignatureFailureKind::SecureEnclaveUnavailable => "secure enclave unavailable",
            SignatureFailureKind::SecureEnclaveRejectedKey => "secure enclave rejected key",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a key agreement operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAgreementFailureKind {
    /// Deriving the shared secret did not succeed.
    DeriveSharedSecretFailed,
    /// Key generation did not succeed.
    KeyGenerationFailed,
}

impl core::fmt::Display for KeyAgreementFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KeyAgreementFailureKind::DeriveSharedSecretFailed => "derive shared secret failed",
            KeyAgreementFailureKind::KeyGenerationFailed => "key generation failed",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a KEM (key encapsulation) operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KemFailureKind {
    /// Key generation did not succeed.
    KeyGenerationFailed,
    /// Encapsulation did not succeed.
    EncapsulateFailed,
    /// Decapsulation did not succeed.
    DecapsulateFailed,
}

impl core::fmt::Display for KemFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            KemFailureKind::KeyGenerationFailed => "key generation failed",
            KemFailureKind::EncapsulateFailed => "encapsulate failed",
            KemFailureKind::DecapsulateFailed => "decapsulate failed",
        };
        write!(f, "{detail}")
    }
}
