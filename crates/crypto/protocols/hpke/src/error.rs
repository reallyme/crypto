// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Domain-specific HPKE error.
///
/// Backend errors are deliberately collapsed into fixed variants so FFI and
/// telemetry never receive arbitrary strings from a crypto provider.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HpkeError {
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
    /// A caller-supplied output length calculation overflowed.
    #[error("HPKE length overflow")]
    LengthOverflow,
    /// Encryption failed in the backend provider.
    #[error("HPKE seal failed")]
    SealFailed,
    /// Authentication or decryption failed in the backend provider.
    #[error("HPKE open failed")]
    OpenFailed,
    /// Vector-generation randomness has the wrong suite-specific length.
    #[error("invalid deterministic HPKE randomness")]
    InvalidRandomness,
}
