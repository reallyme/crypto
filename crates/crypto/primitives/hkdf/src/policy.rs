// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};

/// Selects the hash function backing an HKDF operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HkdfSuite {
    /// HKDF using SHA-256.
    Sha2_256,
    /// HKDF using SHA3-256.
    Sha3_256,
}

impl HkdfSuite {
    /// Return the [`HkdfHash`] backing this suite.
    pub const fn hash(self) -> HkdfHash {
        match self {
            Self::Sha2_256 => HkdfHash::Sha2_256,
            Self::Sha3_256 => HkdfHash::Sha3_256,
        }
    }
}

/// Named purpose that binds a derived domain key to a specific use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainKeyPurpose {
    /// Key used to encrypt content with an AEAD.
    AeadContentKey,
    /// Key used to wrap (encrypt) other keys with an AEAD.
    AeadWrapKey,
    /// Key used to produce authentication proofs.
    AuthProofKey,
    /// Key used to commit to a manifest.
    ManifestCommitmentKey,
}

impl DomainKeyPurpose {
    pub(crate) const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::AeadContentKey => b"aead_content_key",
            Self::AeadWrapKey => b"aead_wrap_key",
            Self::AuthProofKey => b"auth_proof_key",
            Self::ManifestCommitmentKey => b"manifest_commitment_key",
        }
    }
}

/// Validated domain-separation tag appended to derived-key `info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainTag {
    bytes: Vec<u8>,
}

impl DomainTag {
    /// Build a domain tag, requiring 1..=48 bytes drawn only from lowercase
    /// ASCII letters, digits, and `/`, `_`, or `-`; otherwise returns an error.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.is_empty() || input.len() > 48 {
            return Err(CryptoError::Hkdf {
                hash: HkdfHash::Sha3_256,
                kind: HkdfFailureKind::InvalidDomainTagLength,
            });
        }

        for byte in input {
            let is_lower_alpha = byte.is_ascii_lowercase();
            let is_digit = byte.is_ascii_digit();
            let is_punctuation = matches!(*byte, b'/' | b'_' | b'-');
            if !(is_lower_alpha || is_digit || is_punctuation) {
                return Err(CryptoError::Hkdf {
                    hash: HkdfHash::Sha3_256,
                    kind: HkdfFailureKind::InvalidDomainTagByte,
                });
            }
        }

        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    /// Borrow the domain tag bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
