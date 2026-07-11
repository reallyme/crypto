// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use js_sys::Uint8Array;
use zeroize::Zeroize;

use crate::{CiphertextWithTag, EncryptRequest, AES_256_GCM_TAG_LENGTH};

use super::bindings::js_aes256_gcm_encrypt;

/// Encrypts with AES-256-GCM through the JavaScript host provider.
pub fn encrypt(request: &EncryptRequest<'_>) -> Result<CiphertextWithTag, CryptoError> {
    let key = Uint8Array::from(request.key.as_bytes().as_ref());
    let nonce = Uint8Array::from(request.nonce.as_bytes().as_ref());
    let aad = Uint8Array::from(request.aad);
    let plaintext = Uint8Array::from(request.plaintext);

    let mut encrypted = js_aes256_gcm_encrypt(key, nonce, aad, plaintext)
        .map_err(|_| CryptoError::AeadEncrypt {
            backend: AeadBackend::Wasm,
            kind: AeadFailureKind::BackendFailure,
        })?
        .to_vec();

    if encrypted.len() < AES_256_GCM_TAG_LENGTH {
        encrypted.zeroize();
        return Err(CryptoError::AeadEncrypt {
            backend: AeadBackend::Wasm,
            kind: AeadFailureKind::ShortCiphertext,
        });
    }

    CiphertextWithTag::from_vec(encrypted)
}
