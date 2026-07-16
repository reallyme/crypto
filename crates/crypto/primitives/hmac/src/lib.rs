// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HMAC (RFC 2104 / FIPS 198-1) over SHA-256 and SHA-512.
//!
//! The `native` and `wasm` lanes intentionally use the same audited RustCrypto
//! implementation for byte-for-byte semantics.

#![forbid(unsafe_code)]

mod types;

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{authenticate, verify};

pub use types::{
    HmacKey, HmacTag, HMAC_MAX_KEY_LENGTH, HMAC_SHA256_TAG_LENGTH, HMAC_SHA512_TAG_LENGTH,
};
