// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-GCM facade routes backed by the semantic AEAD operation owner.

use crypto_core::{AeadAlgorithm, CryptoError};

use crate::aead_error::{crypto_error_from_operation_error, invalid_output_error, AeadOperation};

pub use crypto_aes256_gcm::{
    Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey, Aes128GcmNonce,
    Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey,
    Aes256GcmNonce, CiphertextWithTag, DecryptRequest, EncryptRequest, AES_128_GCM_KEY_LENGTH,
    AES_128_GCM_NONCE_LENGTH, AES_128_GCM_TAG_LENGTH, AES_192_GCM_KEY_LENGTH,
    AES_192_GCM_NONCE_LENGTH, AES_192_GCM_TAG_LENGTH, AES_256_GCM_KEY_LENGTH,
    AES_256_GCM_NONCE_LENGTH, AES_256_GCM_TAG_LENGTH,
};

/// Encrypts with AES-128-GCM through the operation layer.
pub fn encrypt_aes128_gcm(
    request: &Aes128GcmEncryptRequest<'_>,
) -> Result<CiphertextWithTag, CryptoError> {
    seal(
        AeadAlgorithm::Aes128Gcm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.plaintext,
    )
}

/// Decrypts with AES-128-GCM through the operation layer.
pub fn decrypt_aes128_gcm(request: &Aes128GcmDecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    open(
        AeadAlgorithm::Aes128Gcm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

/// Encrypts with AES-192-GCM through the operation layer.
pub fn encrypt_aes192_gcm(
    request: &Aes192GcmEncryptRequest<'_>,
) -> Result<CiphertextWithTag, CryptoError> {
    seal(
        AeadAlgorithm::Aes192Gcm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.plaintext,
    )
}

/// Decrypts with AES-192-GCM through the operation layer.
pub fn decrypt_aes192_gcm(request: &Aes192GcmDecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    open(
        AeadAlgorithm::Aes192Gcm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

/// Encrypts with AES-256-GCM through the operation layer.
pub fn encrypt(request: &EncryptRequest<'_>) -> Result<CiphertextWithTag, CryptoError> {
    seal(
        AeadAlgorithm::Aes256Gcm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.plaintext,
    )
}

/// Decrypts with AES-256-GCM through the operation layer.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    open(
        AeadAlgorithm::Aes256Gcm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

fn seal(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<CiphertextWithTag, CryptoError> {
    let bytes =
        crate::operations::aead::seal(algorithm, key, nonce, aad, plaintext).map_err(|error| {
            crypto_error_from_operation_error(
                algorithm,
                AeadOperation::Seal,
                error,
                key.len(),
                nonce.len(),
                plaintext.len(),
            )
        })?;
    CiphertextWithTag::from_vec(bytes).map_err(|_| invalid_output_error(AeadOperation::Seal))
}

fn open(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    crate::operations::aead::open(algorithm, key, nonce, aad, ciphertext)
        .map(|plaintext| plaintext.to_vec())
        .map_err(|error| {
            crypto_error_from_operation_error(
                algorithm,
                AeadOperation::Open,
                error,
                key.len(),
                nonce.len(),
                ciphertext.len(),
            )
        })
}
