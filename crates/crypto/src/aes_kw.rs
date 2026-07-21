// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! AES-KW facade routes backed by the semantic key-wrap operation owner.

use crypto_core::{CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation};

pub use crypto_aes_kw::{
    Aes128KwKek, Aes192KwKek, Aes256KwKek, AesKwKeyData, AesKwWrappedKey, AES_128_KW_KEK_LENGTH,
    AES_192_KW_KEK_LENGTH, AES_256_KW_KEK_LENGTH, AES_KW_BLOCK_LENGTH,
    AES_KW_INTEGRITY_CHECK_LENGTH, AES_KW_MAX_KEY_DATA_LENGTH, AES_KW_MIN_KEY_DATA_LENGTH,
    AES_KW_MIN_WRAPPED_KEY_LENGTH,
};

/// Wraps plaintext key material with AES-256-KW through the operation layer.
pub fn wrap_key(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    wrap_key_aes256(kek, key_data)
}

/// Wraps plaintext key material with AES-128-KW through the operation layer.
pub fn wrap_key_aes128(kek: &Aes128KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    wrap_with(KeyWrapAlgorithm::Aes128Kw, kek.as_bytes(), key_data)
}

/// Wraps plaintext key material with AES-192-KW through the operation layer.
pub fn wrap_key_aes192(kek: &Aes192KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    wrap_with(KeyWrapAlgorithm::Aes192Kw, kek.as_bytes(), key_data)
}

/// Wraps plaintext key material with AES-256-KW through the operation layer.
pub fn wrap_key_aes256(kek: &Aes256KwKek, key_data: &[u8]) -> Result<AesKwWrappedKey, CryptoError> {
    wrap_with(KeyWrapAlgorithm::Aes256Kw, kek.as_bytes(), key_data)
}

/// Unwraps RFC 3394 AES-256-KW wrapped key material through the operation layer.
pub fn unwrap_key(kek: &Aes256KwKek, wrapped_key: &[u8]) -> Result<AesKwKeyData, CryptoError> {
    unwrap_key_aes256(kek, wrapped_key)
}

/// Unwraps RFC 3394 AES-128-KW wrapped key material through the operation layer.
pub fn unwrap_key_aes128(
    kek: &Aes128KwKek,
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    unwrap_with(KeyWrapAlgorithm::Aes128Kw, kek.as_bytes(), wrapped_key)
}

/// Unwraps RFC 3394 AES-192-KW wrapped key material through the operation layer.
pub fn unwrap_key_aes192(
    kek: &Aes192KwKek,
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    unwrap_with(KeyWrapAlgorithm::Aes192Kw, kek.as_bytes(), wrapped_key)
}

/// Unwraps RFC 3394 AES-256-KW wrapped key material through the operation layer.
pub fn unwrap_key_aes256(
    kek: &Aes256KwKek,
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    unwrap_with(KeyWrapAlgorithm::Aes256Kw, kek.as_bytes(), wrapped_key)
}

fn wrap_with(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
    key_data: &[u8],
) -> Result<AesKwWrappedKey, CryptoError> {
    crate::operations::key_wrap::wrap_key(algorithm, kek, key_data).map_err(|error| {
        crypto_error_from_operation_error(algorithm, KeyWrapOperation::Wrap, error)
    })
}

fn unwrap_with(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
    wrapped_key: &[u8],
) -> Result<AesKwKeyData, CryptoError> {
    crate::operations::key_wrap::unwrap_key(algorithm, kek, wrapped_key).map_err(|error| {
        crypto_error_from_operation_error(algorithm, KeyWrapOperation::Unwrap, error)
    })
}

fn crypto_error_from_operation_error(
    algorithm: KeyWrapAlgorithm,
    operation: KeyWrapOperation,
    error: crate::operations::OperationError,
) -> CryptoError {
    let kind = match error {
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidKey,
        } => KeyWrapFailureKind::InvalidKekLength,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::InvalidLength,
        } => match operation {
            KeyWrapOperation::Wrap => KeyWrapFailureKind::InvalidPlaintextLength,
            KeyWrapOperation::Unwrap => KeyWrapFailureKind::InvalidWrappedLength,
            _ => KeyWrapFailureKind::BackendFailure,
        },
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::LengthOverflow,
        } => KeyWrapFailureKind::LengthOverflow,
        crate::operations::OperationError::Primitive {
            reason: crate::operations::PrimitiveErrorReason::VerificationFailed,
        } => KeyWrapFailureKind::IntegrityCheckFailed,
        crate::operations::OperationError::Provider {
            reason: crate::operations::ProviderErrorReason::UnsupportedAlgorithm,
        } => return CryptoError::Unsupported,
        _ => KeyWrapFailureKind::BackendFailure,
    };

    CryptoError::KeyWrap {
        algorithm,
        operation,
        kind,
    }
}
