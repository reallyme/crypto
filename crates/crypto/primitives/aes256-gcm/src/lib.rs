// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM authenticated encryption. Nonce uniqueness is the caller's responsibility; use AES-256-GCM-SIV when uniqueness cannot be guaranteed.

mod types;
pub use types::{
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    AES_256_GCM_KEY_LENGTH, AES_256_GCM_NONCE_LENGTH, AES_256_GCM_TAG_LENGTH,
};

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{decrypt, encrypt};

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub use wasm::{decrypt, encrypt};
