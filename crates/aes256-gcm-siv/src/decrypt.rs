// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use aes_gcm_siv::aead::{AeadInOut, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce, Tag};
use crypto_core::{authenticate_record, CryptoError};
use zeroize::Zeroizing;

use crate::types::DecryptRequest;
use crate::AES_256_GCM_SIV_TAG_LENGTH;

/// Decrypts and authenticates an AES-256-GCM-SIV ciphertext, returning the
/// recovered plaintext. Fails closed with an error on invalid key material or
/// if authentication of the ciphertext/AAD fails.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    decrypt_zeroizing(request).map(|mut plaintext| core::mem::take(&mut *plaintext))
}

/// Decrypts AES-256-GCM-SIV and owns plaintext in a buffer wiped on drop.
pub fn decrypt_zeroizing(request: &DecryptRequest<'_>) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());
    let cipher = Aes256GcmSiv::new_from_slice(&*key_material)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let nonce = Nonce::from(*request.nonce.as_bytes());
    authenticate_record::<AES_256_GCM_SIV_TAG_LENGTH>(
        request.ciphertext.as_bytes(),
        |output, tag| {
            cipher
                .decrypt_inout_detached(&nonce, request.aad, output.into(), &Tag::from(*tag))
                .map_err(|_| CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
        },
    )
}
