// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SHA3-256 (FIPS 202) digest wrapper.

mod digest;

pub use digest::{digest, Sha3_256Digest, SHA3_256_DIGEST_LENGTH};
