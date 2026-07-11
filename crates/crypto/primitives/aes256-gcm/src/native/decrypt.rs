// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use zeroize::Zeroizing;

use crate::DecryptRequest;

/// Decrypts and authenticates an AES-256-GCM ciphertext via the native backend,
/// returning the recovered plaintext. Fails closed with an error on invalid key
/// material or if authentication of the ciphertext/AAD fails.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());

    let cipher =
        Aes256Gcm::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadDecrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::InvalidKeyMaterial,
        })?;

    let nonce: Nonce<U12> = (*request.nonce.as_bytes()).into();

    let payload = Payload {
        msg: request.ciphertext.as_bytes(),
        aad: request.aad,
    };

    cipher
        .decrypt(&nonce, payload)
        .map_err(|_| CryptoError::AeadDecrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::AuthenticationFailed,
        })
}
