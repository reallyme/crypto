// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SHA-256 (FIPS 180-4) digest wrapper.

mod digest;

pub use digest::{digest, Sha2_256Digest, SHA2_256_DIGEST_LENGTH};
