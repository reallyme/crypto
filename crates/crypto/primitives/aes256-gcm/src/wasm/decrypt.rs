// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use js_sys::Uint8Array;

use crate::{Aes128GcmDecryptRequest, Aes192GcmDecryptRequest, DecryptRequest};

use super::bindings::{js_aes128_gcm_decrypt, js_aes192_gcm_decrypt, js_aes256_gcm_decrypt};

/// Decrypts with AES-128-GCM through the JavaScript host provider.
pub fn decrypt_aes128_gcm(request: &Aes128GcmDecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let key = Uint8Array::from(request.key.as_bytes().as_ref());
    let nonce = Uint8Array::from(request.nonce.as_bytes().as_ref());
    let aad = Uint8Array::from(request.aad);
    let ciphertext = Uint8Array::from(request.ciphertext.as_bytes());

    js_aes128_gcm_decrypt(key, nonce, aad, ciphertext)
        .map_err(|_| CryptoError::AeadDecrypt {
            backend: AeadBackend::Wasm,
            kind: AeadFailureKind::AuthenticationFailed,
        })
        .map(|bytes| bytes.to_vec())
}

/// Decrypts with AES-192-GCM through the JavaScript host provider.
pub fn decrypt_aes192_gcm(request: &Aes192GcmDecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let key = Uint8Array::from(request.key.as_bytes().as_ref());
    let nonce = Uint8Array::from(request.nonce.as_bytes().as_ref());
    let aad = Uint8Array::from(request.aad);
    let ciphertext = Uint8Array::from(request.ciphertext.as_bytes());

    js_aes192_gcm_decrypt(key, nonce, aad, ciphertext)
        .map_err(|_| CryptoError::AeadDecrypt {
            backend: AeadBackend::Wasm,
            kind: AeadFailureKind::AuthenticationFailed,
        })
        .map(|bytes| bytes.to_vec())
}

/// Decrypts with AES-256-GCM through the JavaScript host provider.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let key = Uint8Array::from(request.key.as_bytes().as_ref());
    let nonce = Uint8Array::from(request.nonce.as_bytes().as_ref());
    let aad = Uint8Array::from(request.aad);
    let ciphertext = Uint8Array::from(request.ciphertext.as_bytes());

    js_aes256_gcm_decrypt(key, nonce, aad, ciphertext)
        .map_err(|_| CryptoError::AeadDecrypt {
            backend: AeadBackend::Wasm,
            kind: AeadFailureKind::AuthenticationFailed,
        })
        .map(|bytes| bytes.to_vec())
}
