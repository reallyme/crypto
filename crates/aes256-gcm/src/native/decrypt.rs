// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce, Tag};
use crypto_core::{authenticate_record, CryptoError};
use zeroize::Zeroizing;

use crate::{
    Aes128GcmDecryptRequest, Aes192GcmDecryptRequest, DecryptRequest, AES_256_GCM_TAG_LENGTH,
};

type Aes192Gcm = AesGcm<aes::Aes192, U12>;

/// Decrypts and authenticates an AES-128-GCM ciphertext via the native backend.
pub fn decrypt_aes128_gcm(request: &Aes128GcmDecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    decrypt_aes128_gcm_zeroizing(request).map(|mut plaintext| core::mem::take(&mut *plaintext))
}

/// Decrypts AES-128-GCM and owns plaintext in a buffer wiped on drop.
pub fn decrypt_aes128_gcm_zeroizing(
    request: &Aes128GcmDecryptRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());
    let cipher = Aes128Gcm::new_from_slice(&*key_material)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    open(
        &cipher,
        &(*request.nonce.as_bytes()).into(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

/// Decrypts and authenticates an AES-192-GCM ciphertext via the native backend.
pub fn decrypt_aes192_gcm(request: &Aes192GcmDecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    decrypt_aes192_gcm_zeroizing(request).map(|mut plaintext| core::mem::take(&mut *plaintext))
}

/// Decrypts AES-192-GCM and owns plaintext in a buffer wiped on drop.
pub fn decrypt_aes192_gcm_zeroizing(
    request: &Aes192GcmDecryptRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());
    let cipher = Aes192Gcm::new_from_slice(&*key_material)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    open(
        &cipher,
        &(*request.nonce.as_bytes()).into(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

/// Decrypts and authenticates an AES-256-GCM ciphertext via the native backend,
/// returning the recovered plaintext. Fails closed with an error on invalid key
/// material or if authentication of the ciphertext/AAD fails.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    decrypt_zeroizing(request).map(|mut plaintext| core::mem::take(&mut *plaintext))
}

/// Decrypts AES-256-GCM and owns plaintext in a buffer wiped on drop.
pub fn decrypt_zeroizing(request: &DecryptRequest<'_>) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_material = Zeroizing::new(*request.key.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&*key_material)
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    open(
        &cipher,
        &(*request.nonce.as_bytes()).into(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

fn open(
    cipher: &impl AeadInOut<NonceSize = U12, TagSize = U16>,
    nonce: &Nonce<U12>,
    aad: &[u8],
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    authenticate_record::<AES_256_GCM_TAG_LENGTH>(record, |output, tag| {
        cipher
            .decrypt_inout_detached(nonce, aad, output.into(), &Tag::from(*tag))
            .map_err(|_| CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
    })
}
