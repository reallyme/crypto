// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, MacAlgorithm, MacFailureKind, MacHash};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length in bytes of an HMAC-SHA-256 tag.
pub const HMAC_SHA256_TAG_LENGTH: usize = 32;
/// Length in bytes of an HMAC-SHA-384 tag.
pub const HMAC_SHA384_TAG_LENGTH: usize = 48;
/// Length in bytes of an HMAC-SHA-512 tag.
pub const HMAC_SHA512_TAG_LENGTH: usize = 64;
/// Maximum accepted HMAC key length in bytes.
///
/// HMAC itself permits arbitrary-length keys, but the public API caps accepted
/// key material so boundary callers cannot force unbounded allocation. Long
/// keys above the SHA-512 block size are already hashed by HMAC internally.
pub const HMAC_MAX_KEY_LENGTH: usize = 4096;

/// HMAC key material.
///
/// The key is copied into an owned zeroizing buffer before use so callers can
/// drop their input independently and the primitive controls memory cleanup.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl HmacKey {
    /// Constructs an HMAC key from raw bytes.
    ///
    /// Empty keys are rejected because they provide no secret entropy. Very
    /// large keys are rejected to keep allocation behavior deterministic at
    /// FFI and platform boundaries.
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.is_empty() || input.len() > HMAC_MAX_KEY_LENGTH {
            return Err(CryptoError::Mac {
                hash: MacHash::Sha2_256,
                kind: MacFailureKind::InvalidKeyLength,
            });
        }

        Ok(Self {
            bytes: Zeroizing::new(input.to_vec()),
        })
    }

    /// Borrows the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// HMAC authentication tag bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HmacTag {
    bytes: [u8; HMAC_SHA512_TAG_LENGTH],
    len: usize,
}

impl PartialEq for HmacTag {
    fn eq(&self, other: &Self) -> bool {
        // Compare the complete fixed-capacity representation as well as the
        // public tag length so `==` cannot become a prefix timing oracle for
        // downstream callers that compare computed and received MACs.
        bool::from(self.bytes.ct_eq(&other.bytes) & self.len.ct_eq(&other.len))
    }
}

impl Eq for HmacTag {}

impl HmacTag {
    /// Constructs a tag from fixed-size bytes for `algorithm`.
    pub fn from_slice(algorithm: MacAlgorithm, input: &[u8]) -> Result<Self, CryptoError> {
        let expected = tag_length(algorithm);
        if input.len() != expected {
            return Err(CryptoError::Mac {
                hash: mac_hash(algorithm),
                kind: MacFailureKind::InvalidTagLength,
            });
        }

        let mut bytes = [0u8; HMAC_SHA512_TAG_LENGTH];
        bytes[..expected].copy_from_slice(input);
        Ok(Self {
            bytes,
            len: expected,
        })
    }

    /// Borrows the tag bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the tag length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether this tag contains zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Consumes the tag and returns the owned tag bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl core::fmt::Debug for HmacTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HmacTag(len={})", self.len)
    }
}

pub(crate) fn tag_length(algorithm: MacAlgorithm) -> usize {
    match algorithm {
        MacAlgorithm::HmacSha256 => HMAC_SHA256_TAG_LENGTH,
        MacAlgorithm::HmacSha384 => HMAC_SHA384_TAG_LENGTH,
        MacAlgorithm::HmacSha512 => HMAC_SHA512_TAG_LENGTH,
    }
}

pub(crate) fn mac_hash(algorithm: MacAlgorithm) -> MacHash {
    match algorithm {
        MacAlgorithm::HmacSha256 => MacHash::Sha2_256,
        MacAlgorithm::HmacSha384 => MacHash::Sha2_384,
        MacAlgorithm::HmacSha512 => MacHash::Sha2_512,
    }
}
