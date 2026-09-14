// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA3-256 (FIPS 202) digest wrapper.

mod digest;

pub use digest::{digest, Sha3_256Digest, SHA3_256_DIGEST_LENGTH};
