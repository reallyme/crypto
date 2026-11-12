// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a SHA-256 digest.
pub const SHA2_256_DIGEST_LENGTH: usize = 32;

/// SHA-256 digest bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Sha2_256Digest {
    bytes: [u8; SHA2_256_DIGEST_LENGTH],
}

impl Sha2_256Digest {
    /// Borrow the fixed-size digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA2_256_DIGEST_LENGTH] {
        &self.bytes
    }

    /// Consume the digest and return its fixed-size byte array.
    ///
    /// The caller owns the returned array and its cleanup responsibility.
    pub fn into_bytes(self) -> [u8; SHA2_256_DIGEST_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for Sha2_256Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sha2_256Digest(len={})", SHA2_256_DIGEST_LENGTH)
    }
}

/// Compute SHA-256 digest bytes for `message`.
pub fn digest(message: &[u8]) -> Sha2_256Digest {
    // Guard the destination before compression/finalization can write to it.
    let mut digest = Sha2_256Digest {
        bytes: [0u8; SHA2_256_DIGEST_LENGTH],
    };
    crate::hash_message::hash(message, &mut digest.bytes);
    digest
}
