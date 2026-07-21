// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-GCM authenticated encryption for 128-bit, 192-bit, and 256-bit keys. Nonce
//! uniqueness is the caller's responsibility; use AES-256-GCM-SIV when
//! uniqueness cannot be guaranteed.

mod types;
pub use types::{
    Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey, Aes128GcmNonce,
    Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey,
    Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest, AES_128_GCM_KEY_LENGTH,
    AES_128_GCM_NONCE_LENGTH, AES_128_GCM_TAG_LENGTH, AES_192_GCM_KEY_LENGTH,
    AES_192_GCM_NONCE_LENGTH, AES_192_GCM_TAG_LENGTH, AES_256_GCM_KEY_LENGTH,
    AES_256_GCM_NONCE_LENGTH, AES_256_GCM_TAG_LENGTH,
};

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm,
};
