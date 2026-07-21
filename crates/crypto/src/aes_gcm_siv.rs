// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM-SIV facade routes backed by the semantic AEAD operation owner.

use crypto_core::{AeadAlgorithm, CryptoError};

use crate::aead_error::{crypto_error_from_operation_error, invalid_output_error, AeadOperation};

pub use crypto_aes256_gcm_siv::{
    Aes256GcmSivKey, Aes256GcmSivNonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    AES_256_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_NONCE_LENGTH, AES_256_GCM_SIV_TAG_LENGTH,
};

/// Encrypts with AES-256-GCM-SIV through the operation layer.
pub fn encrypt(request: &EncryptRequest<'_>) -> Result<CiphertextWithTag, CryptoError> {
    let algorithm = AeadAlgorithm::Aes256GcmSiv;
    let bytes = crate::operations::aead::seal(
        algorithm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.plaintext,
    )
    .map_err(|error| {
        crypto_error_from_operation_error(
            algorithm,
            AeadOperation::Seal,
            error,
            request.key.as_bytes().len(),
            request.nonce.as_bytes().len(),
            request.plaintext.len(),
        )
    })?;
    CiphertextWithTag::from_vec(bytes).map_err(|_| invalid_output_error(AeadOperation::Seal))
}

/// Decrypts with AES-256-GCM-SIV through the operation layer.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    let algorithm = AeadAlgorithm::Aes256GcmSiv;
    crate::operations::aead::open(
        algorithm,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
    .map(|plaintext| plaintext.to_vec())
    .map_err(|error| {
        crypto_error_from_operation_error(
            algorithm,
            AeadOperation::Open,
            error,
            request.key.as_bytes().len(),
            request.nonce.as_bytes().len(),
            request.ciphertext.as_bytes().len(),
        )
    })
}
