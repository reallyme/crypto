// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(
    feature = "dispatch",
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
use crypto_core::{AeadAlgorithm, CryptoError};

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
use crate::operations::OperationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadOperation {
    Seal,
    Open,
}

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
pub(crate) fn crypto_error_from_operation_error(
    _algorithm: AeadAlgorithm,
    _operation: AeadOperation,
    error: OperationError,
    _key_len: usize,
    _nonce_len: usize,
    _input_len: usize,
) -> CryptoError {
    error
}

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
pub(crate) fn invalid_output_error(_operation: AeadOperation) -> CryptoError {
    CryptoError::BACKEND_INVALID_STATE
}
