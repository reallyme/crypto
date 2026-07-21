// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ChaCha20-Poly1305 facade routes backed by the semantic AEAD operation owner.

use crypto_core::{AeadAlgorithm, CryptoError};

use crate::aead_error::{crypto_error_from_operation_error, invalid_output_error, AeadOperation};

pub use crypto_chacha20_poly1305::{
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, CiphertextWithTag, DecryptRequest, EncryptRequest,
    XChaCha20Poly1305DecryptRequest, XChaCha20Poly1305EncryptRequest, XChaCha20Poly1305Nonce,
    CHACHA20_POLY1305_KEY_LENGTH, CHACHA20_POLY1305_NONCE_LENGTH, CHACHA20_POLY1305_TAG_LENGTH,
    XCHACHA20_POLY1305_NONCE_LENGTH,
};

/// Encrypts with ChaCha20-Poly1305 through the operation layer.
pub fn encrypt(request: &EncryptRequest<'_>) -> Result<CiphertextWithTag, CryptoError> {
    seal(
        AeadAlgorithm::ChaCha20Poly1305,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.plaintext,
    )
}

/// Decrypts with ChaCha20-Poly1305 through the operation layer.
pub fn decrypt(request: &DecryptRequest<'_>) -> Result<Vec<u8>, CryptoError> {
    open(
        AeadAlgorithm::ChaCha20Poly1305,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.ciphertext.as_bytes(),
    )
}

/// Encrypts with XChaCha20-Poly1305 through the operation layer.
pub fn encrypt_xchacha20_poly1305(
    request: &XChaCha20Poly1305EncryptRequest<'_>,
) -> Result<CiphertextWithTag, CryptoError> {
    seal(
        AeadAlgorithm::XChaCha20Poly1305,
        request.key.as_bytes(),
        request.nonce.as_bytes(),
        request.aad,
        request.plaintext,
    )
}

/// Decrypts with XChaCha20-Poly1305 through the operation layer.
pub fn decrypt_xchacha20_poly1305(
    request: &XChaCha20Poly1305DecryptRequest<'_>,
) -> Result<Vec<u8>, CryptoError> {
    open(
        AeadAlgorithm::XChaCha20Poly1305,
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
