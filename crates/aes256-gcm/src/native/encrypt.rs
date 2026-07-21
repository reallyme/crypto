// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use zeroize::Zeroizing;

use crate::{Aes128GcmEncryptRequest, Aes192GcmEncryptRequest, CiphertextWithTag, EncryptRequest};

type Aes192Gcm = AesGcm<aes::Aes192, U12>;

/// Encrypts a plaintext with AES-128-GCM via the native backend, returning the
/// `ciphertext || tag`.
pub fn encrypt_aes128_gcm(
    request: &Aes128GcmEncryptRequest<'_>,
) -> Result<CiphertextWithTag, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());

    let cipher =
        Aes128Gcm::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadEncrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::InvalidKeyMaterial,
        })?;

    let nonce: Nonce<U12> = (*request.nonce.as_bytes()).into();

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

/// Encrypts a plaintext with AES-192-GCM via the native backend, returning the
/// `ciphertext || tag`.
pub fn encrypt_aes192_gcm(
    request: &Aes192GcmEncryptRequest<'_>,
) -> Result<CiphertextWithTag, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());

    let cipher =
        Aes192Gcm::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadEncrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::InvalidKeyMaterial,
        })?;

    let nonce: Nonce<U12> = (*request.nonce.as_bytes()).into();

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

/// Encrypts a plaintext with AES-256-GCM via the native backend, returning the
/// `ciphertext || tag`. Fails with an error on invalid key material or backend
/// failure.
pub fn encrypt(request: &EncryptRequest<'_>) -> Result<CiphertextWithTag, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());

    let cipher =
        Aes256Gcm::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadEncrypt {
            backend: AeadBackend::Native,
            kind: AeadFailureKind::InvalidKeyMaterial,
        })?;

    let nonce: Nonce<U12> = (*request.nonce.as_bytes()).into();

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
