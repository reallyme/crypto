// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA-384 and SHA-512 (FIPS 180-4) digest wrappers.

#![forbid(unsafe_code)]

mod digest;

pub use digest::{
    digest_sha2_384, digest_sha2_512, Sha2_384Digest, Sha2_512Digest, SHA2_384_DIGEST_LENGTH,
    SHA2_512_DIGEST_LENGTH,
};
