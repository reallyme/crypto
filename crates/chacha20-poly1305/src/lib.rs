// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 authenticated
//! encryption.
//!
//! The Rust `native` and `wasm` lanes intentionally use the same audited
//! RustCrypto implementation. Swift and Kotlin package facades call through
//! FFI/JNI for XChaCha and other AEADs whose provider policy selects Rust.

#![forbid(unsafe_code)]

mod types;

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{decrypt, decrypt_xchacha20_poly1305, encrypt, encrypt_xchacha20_poly1305};

pub use types::{
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    XChaCha20Poly1305DecryptRequest, XChaCha20Poly1305EncryptRequest, XChaCha20Poly1305Nonce,
    CHACHA20_POLY1305_KEY_LENGTH, CHACHA20_POLY1305_NONCE_LENGTH, CHACHA20_POLY1305_TAG_LENGTH,
    XCHACHA20_POLY1305_NONCE_LENGTH,
};
