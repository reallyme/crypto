// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use zeroize::Zeroizing;

use crate::types::DecryptRequest;

/// Decrypts and authenticates an AES-256-GCM-SIV ciphertext, returning the
/// recovered plaintext. Fails closed with an error on invalid key material or
/// if authentication of the ciphertext/AAD fails.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());

    let cipher =
        Aes256GcmSiv::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadDecrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::InvalidKeyMaterial,
        })?;

    let nonce = Nonce::from(*request.nonce.as_bytes());

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
