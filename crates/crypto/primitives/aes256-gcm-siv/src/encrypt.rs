// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use zeroize::Zeroizing;

use crate::types::{CiphertextWithTag, EncryptRequest};

/// Encrypts a plaintext with AES-256-GCM-SIV, returning the `ciphertext || tag`.
/// Fails with an error on invalid key material or backend failure.
pub fn encrypt(request: &EncryptRequest<'_>) -> Result<CiphertextWithTag, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());

    let cipher =
        Aes256GcmSiv::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadEncrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::InvalidKeyMaterial,
        })?;

    let nonce = Nonce::from(*request.nonce.as_bytes());

    let payload = Payload {
        msg: request.plaintext,
        aad: request.aad,
    };

    let encrypted = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::AeadEncrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::BackendFailure,
        })?;

    CiphertextWithTag::from_vec(encrypted)
}
