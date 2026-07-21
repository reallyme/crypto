// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(feature = "native")]

use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt, encrypt_aes128_gcm,
    encrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce,
    Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    AES_128_GCM_TAG_LENGTH, AES_192_GCM_TAG_LENGTH, AES_256_GCM_TAG_LENGTH,
};
use crypto_core::CryptoError;

#[path = "aes256_gcm_tests/errors.rs"]
mod errors;
#[path = "aes256_gcm_tests/roundtrip.rs"]
mod roundtrip;
#[path = "aes256_gcm_tests/vectors.rs"]
mod vector_coverage;
#[path = "vectors.rs"]
mod vectors;

fn test_key() -> Aes256GcmKey {
    let key_bytes = [0x11u8; 32];
    Aes256GcmKey::from_slice(&key_bytes).expect("test key must be valid")
}

fn test_nonce() -> Aes256GcmNonce {
    let nonce_bytes = [0x22u8; 12];
    Aes256GcmNonce::from_slice(&nonce_bytes).expect("test nonce must be valid")
}

fn test_aes128_key() -> Aes128GcmKey {
    let key_bytes = [0x11u8; 16];
    Aes128GcmKey::from_slice(&key_bytes).expect("test key must be valid")
}

fn test_aes128_nonce() -> Aes128GcmNonce {
    let nonce_bytes = [0x22u8; 12];
    Aes128GcmNonce::from_slice(&nonce_bytes).expect("test nonce must be valid")
}

fn test_aes192_key() -> Aes192GcmKey {
    let key_bytes = [0x11u8; 24];
    Aes192GcmKey::from_slice(&key_bytes).expect("test key must be valid")
}

fn test_aes192_nonce() -> Aes192GcmNonce {
    let nonce_bytes = [0x22u8; 12];
    Aes192GcmNonce::from_slice(&nonce_bytes).expect("test nonce must be valid")
}
