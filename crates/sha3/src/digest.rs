// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use sha3::{Digest, Sha3_224, Sha3_384, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a SHA3-224 digest.
pub const SHA3_224_DIGEST_LENGTH: usize = 28;
/// Length in bytes of a SHA3-384 digest.
pub const SHA3_384_DIGEST_LENGTH: usize = 48;
/// Length in bytes of a SHA3-512 digest.
pub const SHA3_512_DIGEST_LENGTH: usize = 64;

/// SHA3-224 digest bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Sha3_224Digest {
    bytes: [u8; SHA3_224_DIGEST_LENGTH],
}

impl Sha3_224Digest {
    /// Borrow the fixed-size digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA3_224_DIGEST_LENGTH] {
        &self.bytes
    }

    /// Consume the digest and return its fixed-size byte array.
    pub fn into_bytes(self) -> [u8; SHA3_224_DIGEST_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for Sha3_224Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sha3_224Digest(len={})", SHA3_224_DIGEST_LENGTH)
    }
}

/// SHA3-384 digest bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Sha3_384Digest {
    bytes: [u8; SHA3_384_DIGEST_LENGTH],
}

impl Sha3_384Digest {
    /// Borrow the fixed-size digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA3_384_DIGEST_LENGTH] {
        &self.bytes
    }

    /// Consume the digest and return its fixed-size byte array.
    pub fn into_bytes(self) -> [u8; SHA3_384_DIGEST_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for Sha3_384Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sha3_384Digest(len={})", SHA3_384_DIGEST_LENGTH)
    }
}

/// SHA3-512 digest bytes.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Sha3_512Digest {
    bytes: [u8; SHA3_512_DIGEST_LENGTH],
}

impl Sha3_512Digest {
    /// Borrow the fixed-size digest bytes.
    pub fn as_bytes(&self) -> &[u8; SHA3_512_DIGEST_LENGTH] {
        &self.bytes
    }

    /// Consume the digest and return its fixed-size byte array.
    pub fn into_bytes(self) -> [u8; SHA3_512_DIGEST_LENGTH] {
        self.bytes
    }
}

impl core::fmt::Debug for Sha3_512Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sha3_512Digest(len={})", SHA3_512_DIGEST_LENGTH)
    }
}

/// Compute SHA3-224 digest bytes for `message`.
pub fn digest_sha3_224(message: &[u8]) -> Sha3_224Digest {
    let mut hasher = Sha3_224::new();
    hasher.update(message);
    let output = hasher.finalize();

    let mut bytes = [0u8; SHA3_224_DIGEST_LENGTH];
    bytes.copy_from_slice(&output);
    Sha3_224Digest { bytes }
}

/// Compute SHA3-384 digest bytes for `message`.
pub fn digest_sha3_384(message: &[u8]) -> Sha3_384Digest {
    let mut hasher = Sha3_384::new();
    hasher.update(message);
    let output = hasher.finalize();

    let mut bytes = [0u8; SHA3_384_DIGEST_LENGTH];
    bytes.copy_from_slice(&output);
    Sha3_384Digest { bytes }
}

/// Compute SHA3-512 digest bytes for `message`.
pub fn digest_sha3_512(message: &[u8]) -> Sha3_512Digest {
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    let output = hasher.finalize();

    let mut bytes = [0u8; SHA3_512_DIGEST_LENGTH];
    bytes.copy_from_slice(&output);
    Sha3_512Digest { bytes }
}
