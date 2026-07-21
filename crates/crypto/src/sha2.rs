// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SHA-2 facade routes backed by the semantic hash operation owner.

pub use crypto_sha2::{
    Sha2_384Digest, Sha2_512Digest, SHA2_384_DIGEST_LENGTH, SHA2_512_DIGEST_LENGTH,
};
pub use crypto_sha2_256::{Sha2_256Digest, SHA2_256_DIGEST_LENGTH};

/// Compute a SHA-256 digest through the operation layer.
#[must_use]
pub fn digest(message: &[u8]) -> Sha2_256Digest {
    crate::operations::hash::sha2_256(message)
}

/// Compute a SHA-384 digest through the operation layer.
#[must_use]
pub fn digest_sha2_384(message: &[u8]) -> Sha2_384Digest {
    crate::operations::hash::sha2_384(message)
}

/// Compute a SHA-512 digest through the operation layer.
#[must_use]
pub fn digest_sha2_512(message: &[u8]) -> Sha2_512Digest {
    crate::operations::hash::sha2_512(message)
}
