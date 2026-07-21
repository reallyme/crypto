// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Domain-specific HPKE error.
///
/// Backend errors are deliberately collapsed into fixed variants so FFI and
/// telemetry never receive arbitrary strings from a crypto provider.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HpkeError {
    /// The KEM identifier is registered but unavailable in this provider.
    #[error("unsupported HPKE KEM")]
    UnsupportedKem,
    /// The KDF identifier is unavailable in this provider.
    #[error("unsupported HPKE KDF")]
    UnsupportedKdf,
    /// The AEAD identifier is unavailable in this provider.
    #[error("unsupported HPKE AEAD")]
    UnsupportedAead,
    /// The requested ciphersuite is not exposed by this crate.
    #[error("unsupported HPKE suite")]
    UnsupportedSuite,
    /// Recipient public key length or encoding is invalid for the suite.
    #[error("invalid HPKE public key")]
    InvalidPublicKey,
    /// Recipient private key length or encoding is invalid for the suite.
    #[error("invalid HPKE private key")]
    InvalidPrivateKey,
    /// Encapsulated key length or encoding is invalid for the suite.
    #[error("invalid HPKE encapsulated key")]
    InvalidEncapsulatedKey,
    /// Ciphertext is too short to contain the required AEAD tag.
    #[error("invalid HPKE ciphertext")]
    InvalidCiphertext,
    /// Deterministic key derivation input has the wrong suite-specific length.
    #[error("invalid HPKE input keying material")]
    InvalidInputKeyMaterial,
    /// The PSK does not satisfy the HPKE high-entropy input contract.
    #[error("invalid HPKE pre-shared key")]
    InvalidPsk,
    /// The PSK identifier is empty or exceeds the key-schedule bound.
    #[error("invalid HPKE pre-shared key identifier")]
    InvalidPskIdentifier,
    /// The `info` and PSK identifier combination exceeds the protocol bound.
    #[error("invalid HPKE info length")]
    InvalidInfoLength,
    /// The requested exporter output length is zero or exceeds its KDF bound.
    #[error("invalid HPKE exporter length")]
    InvalidExporterLength,
    /// The operating system randomness provider was unavailable.
    #[error("HPKE randomness unavailable")]
    RandomnessUnavailable,
    /// A caller-supplied output length calculation overflowed.
    #[error("HPKE length overflow")]
    LengthOverflow,
    /// Encryption failed in the backend provider.
    #[error("HPKE seal failed")]
    SealFailed,
    /// Authentication or decryption failed in the backend provider.
    #[error("HPKE open failed")]
    OpenFailed,
    /// Secret export failed in the backend provider.
    #[error("HPKE export failed")]
    ExportFailed,
    /// Key generation or deterministic derivation produced an invalid shape.
    #[error("HPKE key generation failed")]
    KeyGenerationFailed,
    /// Vector-generation randomness has the wrong suite-specific length.
    #[error("invalid deterministic HPKE randomness")]
    InvalidRandomness,
}
