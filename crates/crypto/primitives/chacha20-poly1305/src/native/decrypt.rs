// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
use crypto_core::{AeadBackend, AeadFailureKind, CryptoError};
use zeroize::Zeroizing;

use crate::{ChaCha20Poly1305Key, DecryptRequest, XChaCha20Poly1305DecryptRequest};

fn chacha20_cipher(key: &ChaCha20Poly1305Key) -> Result<ChaCha20Poly1305, CryptoError> {
    let key_material = Zeroizing::new(*key.as_bytes());
    ChaCha20Poly1305::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadDecrypt {
        backend: AeadBackend::Native,
        kind: AeadFailureKind::InvalidKeyMaterial,
    })
}

fn xchacha20_cipher(key: &ChaCha20Poly1305Key) -> Result<XChaCha20Poly1305, CryptoError> {
    let key_material = Zeroizing::new(*key.as_bytes());
    XChaCha20Poly1305::new_from_slice(&*key_material).map_err(|_| CryptoError::AeadDecrypt {
        backend: AeadBackend::Native,
        kind: AeadFailureKind::InvalidKeyMaterial,
    })
}

/// Decrypts and authenticates a ChaCha20-Poly1305 `ciphertext || tag`.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let cipher = chacha20_cipher(request.key)?;
    let nonce: Nonce = (*request.nonce.as_bytes()).into();
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

/// Decrypts and authenticates an XChaCha20-Poly1305 `ciphertext || tag`.
pub fn decrypt_xchacha20_poly1305(
    request: &XChaCha20Poly1305DecryptRequest<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = xchacha20_cipher(request.key)?;
    let nonce: XNonce = (*request.nonce.as_bytes()).into();
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
