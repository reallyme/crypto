// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM-SIV (RFC 8452) nonce-misuse-resistant AEAD. There is no dedicated browser backend: the `native` and `wasm` lanes both use the audited RustCrypto implementation by design.

#![forbid(unsafe_code)]

mod constants;
mod types;

#[cfg(any(feature = "native", feature = "wasm"))]
mod decrypt;
#[cfg(any(feature = "native", feature = "wasm"))]
mod encrypt;

pub use constants::{
    AES_256_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_NONCE_LENGTH, AES_256_GCM_SIV_TAG_LENGTH,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use decrypt::decrypt;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use encrypt::encrypt;
pub use types::{
    Aes256GcmSivKey, Aes256GcmSivNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
};
