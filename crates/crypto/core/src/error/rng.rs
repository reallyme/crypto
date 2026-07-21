// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Purpose of the random output being generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RngOutputKind {
    /// Generic random bytes with no fixed length.
    Generic,
    /// A 12-byte AEAD nonce.
    AeadNonce12,
    /// A 16-byte Argon2 salt.
    Argon2Salt16,
    /// A 32-byte Argon2 salt.
    Argon2Salt32,
    /// A 32-byte AES-256-GCM key.
    Aes256GcmKey,
    /// A 64-byte ML-KEM-1024 seed.
    MlKem1024Seed,
    /// A 32-byte ML-DSA-87 seed.
    MlDsa87Seed,
    /// A 32-byte Ed25519 private seed.
    Ed25519Seed,
    /// One 16-byte SLH-DSA-SHA2-128s key-generation seed component.
    SlhDsaSha2_128sSeed,
}

impl core::fmt::Display for RngOutputKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            RngOutputKind::Generic => "random bytes",
            RngOutputKind::AeadNonce12 => "AEAD nonce",
            RngOutputKind::Argon2Salt16 => "Argon2 16-byte salt",
            RngOutputKind::Argon2Salt32 => "Argon2 32-byte salt",
            RngOutputKind::Aes256GcmKey => "AES-256-GCM key",
            RngOutputKind::MlKem1024Seed => "ML-KEM-1024 seed",
            RngOutputKind::MlDsa87Seed => "ML-DSA-87 seed",
            RngOutputKind::Ed25519Seed => "Ed25519 seed",
            RngOutputKind::SlhDsaSha2_128sSeed => "SLH-DSA-SHA2-128s seed",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason secure random generation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RngFailureKind {
    /// The system entropy source was unavailable.
    EntropyUnavailable,
    /// The requested output length was unacceptable.
    InvalidOutputLength,
}

impl core::fmt::Display for RngFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            RngFailureKind::EntropyUnavailable => "entropy unavailable",
            RngFailureKind::InvalidOutputLength => "invalid output length",
        };
        write!(f, "{detail}")
    }
}

/// Specific reason a constant-time comparison did not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConstantTimeFailureKind {
    /// The two inputs had different lengths.
    LengthMismatch,
    /// The two inputs had equal length but unequal contents.
    NotEqual,
}

impl core::fmt::Display for ConstantTimeFailureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let detail = match self {
            ConstantTimeFailureKind::LengthMismatch => "length mismatch",
            ConstantTimeFailureKind::NotEqual => "not equal",
        };
        write!(f, "{detail}")
    }
}
