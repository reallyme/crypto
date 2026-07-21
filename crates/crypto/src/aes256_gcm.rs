// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Focused AES-256-GCM facade with typed key and nonce boundaries.
//!
//! This module never generates a nonce. Protocols such as MLS and HPKE derive
//! nonces from their key schedules and must pass the resulting 12-byte value
//! explicitly. For direct use, callers must ensure that a `(key, nonce)` pair
//! is never reused for encryption.

pub use crate::aes::{Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag};
use crate::aes::{DecryptRequest, EncryptRequest};
use crate::CryptoError;

/// AES-256-GCM key length in bytes.
pub const AES_256_GCM_KEY_LEN: usize = crate::aes::AES_256_GCM_KEY_LENGTH;
/// AES-256-GCM nonce length in bytes.
pub const AES_256_GCM_NONCE_LEN: usize = crate::aes::AES_256_GCM_NONCE_LENGTH;
/// AES-256-GCM authentication-tag length in bytes.
pub const AES_256_GCM_TAG_LEN: usize = crate::aes::AES_256_GCM_TAG_LENGTH;

/// Encrypts and authenticates one plaintext using a caller-supplied nonce.
///
/// The returned bytes are `ciphertext || tag`. This function deliberately has
/// no random-nonce overload: MLS and HPKE supply protocol-derived nonces, while
/// direct callers remain responsible for per-key nonce uniqueness.
pub fn aes256_gcm_encrypt(
    key: &Aes256GcmKey,
    nonce: Aes256GcmNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<CiphertextWithTag, CryptoError> {
    crate::aes::encrypt(&EncryptRequest {
        key,
        nonce,
        aad,
        plaintext,
    })
}

/// Authenticates and decrypts one `ciphertext || tag` value.
pub fn aes256_gcm_decrypt(
    key: &Aes256GcmKey,
    nonce: Aes256GcmNonce,
    aad: &[u8],
    ciphertext: &CiphertextWithTag,
) -> Result<Vec<u8>, CryptoError> {
    crate::aes::decrypt(&DecryptRequest {
        key,
        nonce,
        aad,
        ciphertext,
    })
}
