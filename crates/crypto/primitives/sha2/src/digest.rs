// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha384, Sha512};
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
    let mut hasher = Sha384::new();
    hasher.update(message);
    let output = hasher.finalize();

    let mut bytes = [0u8; SHA2_384_DIGEST_LENGTH];
    bytes.copy_from_slice(&output);
    Sha2_384Digest { bytes }
}

/// Compute SHA-512 digest bytes for `message`.
pub fn digest_sha2_512(message: &[u8]) -> Sha2_512Digest {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let output = hasher.finalize();

    let mut bytes = [0u8; SHA2_512_DIGEST_LENGTH];
    bytes.copy_from_slice(&output);
    Sha2_512Digest { bytes }
}
