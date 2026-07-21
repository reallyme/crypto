// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SHA-3 facade routes backed by the semantic hash operation owner.

pub use crypto_sha3::{
    Sha3_224Digest, Sha3_384Digest, Sha3_512Digest, SHA3_224_DIGEST_LENGTH, SHA3_384_DIGEST_LENGTH,
    SHA3_512_DIGEST_LENGTH,
};
pub use crypto_sha3_256::{Sha3_256Digest, SHA3_256_DIGEST_LENGTH};

/// Compute a SHA3-224 digest through the operation layer.
#[must_use]
pub fn digest_sha3_224(message: &[u8]) -> Sha3_224Digest {
    crate::operations::hash::sha3_224(message)
}

/// Compute a SHA3-256 digest through the operation layer.
#[must_use]
pub fn digest(message: &[u8]) -> Sha3_256Digest {
    crate::operations::hash::sha3_256(message)
}

/// Compute a SHA3-384 digest through the operation layer.
#[must_use]
pub fn digest_sha3_384(message: &[u8]) -> Sha3_384Digest {
    crate::operations::hash::sha3_384(message)
}

/// Compute a SHA3-512 digest through the operation layer.
#[must_use]
pub fn digest_sha3_512(message: &[u8]) -> Sha3_512Digest {
    crate::operations::hash::sha3_512(message)
}
