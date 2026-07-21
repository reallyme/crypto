// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! C ABI surface for AES-128/192/256-GCM authenticated encryption.

mod decrypt;
mod encrypt;

pub use decrypt::{
    rm_crypto_aes128_gcm_decrypt, rm_crypto_aes192_gcm_decrypt, rm_crypto_aes256_gcm_decrypt,
};
pub use encrypt::{
    rm_crypto_aes128_gcm_encrypt, rm_crypto_aes192_gcm_encrypt, rm_crypto_aes256_gcm_encrypt,
};

use reallyme_crypto::aes::{
    AES_128_GCM_KEY_LENGTH, AES_128_GCM_NONCE_LENGTH, AES_128_GCM_TAG_LENGTH,
    AES_192_GCM_KEY_LENGTH, AES_192_GCM_NONCE_LENGTH, AES_192_GCM_TAG_LENGTH,
    AES_256_GCM_KEY_LENGTH, AES_256_GCM_NONCE_LENGTH, AES_256_GCM_TAG_LENGTH,
};

/// Length in bytes of an AES-128-GCM key (16).
pub const AES128_GCM_KEY_LEN: usize = AES_128_GCM_KEY_LENGTH;
/// Length in bytes of an AES-128-GCM nonce (12).
pub const AES128_GCM_NONCE_LEN: usize = AES_128_GCM_NONCE_LENGTH;
/// Length in bytes of the AES-128-GCM authentication tag (16).
pub const AES128_GCM_TAG_LEN: usize = AES_128_GCM_TAG_LENGTH;
/// Length in bytes of an AES-192-GCM key (24).
pub const AES192_GCM_KEY_LEN: usize = AES_192_GCM_KEY_LENGTH;
/// Length in bytes of an AES-192-GCM nonce (12).
pub const AES192_GCM_NONCE_LEN: usize = AES_192_GCM_NONCE_LENGTH;
/// Length in bytes of the AES-192-GCM authentication tag (16).
pub const AES192_GCM_TAG_LEN: usize = AES_192_GCM_TAG_LENGTH;
/// Length in bytes of an AES-256-GCM key (32).
pub const AES256_GCM_KEY_LEN: usize = AES_256_GCM_KEY_LENGTH;
/// Length in bytes of an AES-256-GCM nonce (12).
pub const AES256_GCM_NONCE_LEN: usize = AES_256_GCM_NONCE_LENGTH;
/// Length in bytes of the AES-256-GCM authentication tag (16).
pub const AES256_GCM_TAG_LEN: usize = AES_256_GCM_TAG_LENGTH;
