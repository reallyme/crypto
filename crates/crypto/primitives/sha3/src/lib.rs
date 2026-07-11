// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SHA3-224, SHA3-384, and SHA3-512 (FIPS 202) digest wrappers.

#![forbid(unsafe_code)]

mod digest;
mod shake;

pub use digest::{
    digest_sha3_224, digest_sha3_384, digest_sha3_512, Sha3_224Digest, Sha3_384Digest,
    Sha3_512Digest, SHA3_224_DIGEST_LENGTH, SHA3_384_DIGEST_LENGTH, SHA3_512_DIGEST_LENGTH,
};
pub use shake::shake256_expand;
