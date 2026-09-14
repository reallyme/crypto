// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! C ABI surface for AES-128/192/256-GCM authenticated encryption.

mod decrypt;
mod encrypt;

pub use decrypt::{
    rm_crypto_aes128_gcm_decrypt, rm_crypto_aes192_gcm_decrypt, rm_crypto_aes256_gcm_decrypt,
};
pub use encrypt::{
    rm_crypto_aes128_gcm_encrypt, rm_crypto_aes192_gcm_encrypt, rm_crypto_aes256_gcm_encrypt,
};
pub use reallyme_crypto::aes::{
    AES_128_GCM_KEY_LENGTH as AES128_GCM_KEY_LEN, AES_128_GCM_NONCE_LENGTH as AES128_GCM_NONCE_LEN,
    AES_128_GCM_TAG_LENGTH as AES128_GCM_TAG_LEN, AES_192_GCM_KEY_LENGTH as AES192_GCM_KEY_LEN,
    AES_192_GCM_NONCE_LENGTH as AES192_GCM_NONCE_LEN, AES_192_GCM_TAG_LENGTH as AES192_GCM_TAG_LEN,
    AES_256_GCM_KEY_LENGTH as AES256_GCM_KEY_LEN, AES_256_GCM_NONCE_LENGTH as AES256_GCM_NONCE_LEN,
    AES_256_GCM_TAG_LENGTH as AES256_GCM_TAG_LEN,
};
