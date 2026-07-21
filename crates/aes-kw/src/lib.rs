// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-128, AES-192, and AES-256 Key Wrap (RFC 3394 / NIST SP 800-38F).
//!
//! The `native` and `wasm` lanes intentionally use the same audited RustCrypto
//! implementation for byte-for-byte semantics.

#![forbid(unsafe_code)]

mod constants;
mod types;

#[cfg(any(feature = "native", feature = "wasm"))]
mod unwrap_key;
#[cfg(any(feature = "native", feature = "wasm"))]
mod wrap_key;

pub use constants::{
    AES_128_KW_KEK_LENGTH, AES_192_KW_KEK_LENGTH, AES_256_KW_KEK_LENGTH, AES_KW_BLOCK_LENGTH,
    AES_KW_INTEGRITY_CHECK_LENGTH, AES_KW_MAX_KEY_DATA_LENGTH, AES_KW_MIN_KEY_DATA_LENGTH,
    AES_KW_MIN_WRAPPED_KEY_LENGTH,
};
pub use types::{Aes128KwKek, Aes192KwKek, Aes256KwKek, AesKwKeyData, AesKwWrappedKey};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use unwrap_key::{unwrap_key, unwrap_key_aes128, unwrap_key_aes192, unwrap_key_aes256};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use wrap_key::{wrap_key, wrap_key_aes128, wrap_key_aes192, wrap_key_aes256};
