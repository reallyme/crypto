// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag, XChaCha20Poly1305, XNonce};
use crypto_core::{authenticate_record, CryptoError};
use zeroize::Zeroizing;

use crate::{
    ChaCha20Poly1305Key, DecryptRequest, XChaCha20Poly1305DecryptRequest,
    CHACHA20_POLY1305_TAG_LENGTH,
};

fn chacha20_cipher(key: &ChaCha20Poly1305Key) -> Result<ChaCha20Poly1305, CryptoError> {
    let key_material = Zeroizing::new(*key.as_bytes());
    ChaCha20Poly1305::new_from_slice(&*key_material)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)
}

fn xchacha20_cipher(key: &ChaCha20Poly1305Key) -> Result<XChaCha20Poly1305, CryptoError> {
    let key_material = Zeroizing::new(*key.as_bytes());
    XChaCha20Poly1305::new_from_slice(&*key_material)
        .map_err(|_| crypto_core::CryptoError::PRIMITIVE_INVALID_KEY)
}

/// Decrypts and authenticates a ChaCha20-Poly1305 `ciphertext || tag`.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    decrypt_zeroizing(request).map(|mut plaintext| core::mem::take(&mut *plaintext))
}

/// Decrypts ChaCha20-Poly1305 and owns plaintext in a buffer wiped on drop.
pub fn decrypt_zeroizing(request: &DecryptRequest<'_>) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = chacha20_cipher(request.key)?;
    let nonce: Nonce = (*request.nonce.as_bytes()).into();
    authenticate_record::<CHACHA20_POLY1305_TAG_LENGTH>(
        request.ciphertext.as_bytes(),
        |output, tag| {
            cipher
                .decrypt_inout_detached(&nonce, request.aad, output.into(), &Tag::from(*tag))
                .map_err(|_| CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
        },
    )
}

/// Decrypts and authenticates an XChaCha20-Poly1305 `ciphertext || tag`.
pub fn decrypt_xchacha20_poly1305(
    request: &XChaCha20Poly1305DecryptRequest<'_>,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_xchacha20_poly1305_zeroizing(request)
        .map(|mut plaintext| core::mem::take(&mut *plaintext))
}

/// Decrypts XChaCha20-Poly1305 and wipes the plaintext on drop.
pub fn decrypt_xchacha20_poly1305_zeroizing(
    request: &XChaCha20Poly1305DecryptRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = xchacha20_cipher(request.key)?;
    let nonce: XNonce = (*request.nonce.as_bytes()).into();
    authenticate_record::<CHACHA20_POLY1305_TAG_LENGTH>(
        request.ciphertext.as_bytes(),
        |output, tag| {
            cipher
                .decrypt_inout_detached(&nonce, request.aad, output.into(), &Tag::from(*tag))
                .map_err(|_| CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
        },
    )
}
