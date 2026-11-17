// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA-256 (FIPS 180-4) digest wrapper.

mod digest;
mod hash_message;

pub use digest::{digest, Sha2_256Digest, SHA2_256_DIGEST_LENGTH};

mod incremental;

/// Canonical schema-defined failure for incremental hash operations.
pub use crypto_proto::error_types::CryptoError;
pub use incremental::Sha2_256Hasher;
