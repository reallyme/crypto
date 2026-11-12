// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a SHA-384 digest.
pub const SHA2_384_DIGEST_LENGTH: usize = 48;
/// Length in bytes of a SHA-512 digest.
pub const SHA2_512_DIGEST_LENGTH: usize = 64;

/// SHA-384 digest bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Sha2_384Digest {
    bytes: [u8; SHA2_384_DIGEST_LENGTH],
}

impl Sha2_384Digest {
    /// Borrow the fixed-size digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA2_384_DIGEST_LENGTH] {
        &self.bytes
    }

    /// Consume the digest and return its fixed-size byte array.
    ///
    /// The caller owns the returned array and its cleanup responsibility.
    pub fn into_bytes(self) -> [u8; SHA2_384_DIGEST_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for Sha2_384Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sha2_384Digest(len={})", SHA2_384_DIGEST_LENGTH)
    }
}

/// SHA-512 digest bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Sha2_512Digest {
    bytes: [u8; SHA2_512_DIGEST_LENGTH],
}

impl Sha2_512Digest {
    /// Borrow the fixed-size digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA2_512_DIGEST_LENGTH] {
        &self.bytes
    }

    /// Consume the digest and return its fixed-size byte array.
    ///
    /// The caller owns the returned array and its cleanup responsibility.
    pub fn into_bytes(self) -> [u8; SHA2_512_DIGEST_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for Sha2_512Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sha2_512Digest(len={})", SHA2_512_DIGEST_LENGTH)
    }
}

/// Compute SHA-384 digest bytes for `message`.
pub fn digest_sha2_384(message: &[u8]) -> Sha2_384Digest {
    // The existing public owner guards the destination before any digest
    // bytes are written, including when finalization unwinds.
    let mut digest = Sha2_384Digest {
        bytes: [0u8; SHA2_384_DIGEST_LENGTH],
    };
    crate::hash_message::hash(
        message,
        crate::hash_message::SHA384_INITIAL_STATE,
        &mut digest.bytes,
    );
    digest
}

/// Compute SHA-512 digest bytes for `message`.
pub fn digest_sha2_512(message: &[u8]) -> Sha2_512Digest {
    // Keep the output inside its clearing owner instead of staging a second
    // plain byte array on the leaf's stack.
    let mut digest = Sha2_512Digest {
        bytes: [0u8; SHA2_512_DIGEST_LENGTH],
    };
    crate::hash_message::hash(
        message,
        crate::hash_message::SHA512_INITIAL_STATE,
        &mut digest.bytes,
    );
    digest
}
