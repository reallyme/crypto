// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(
    feature = "ed25519",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "rsa",
    feature = "secp256k1",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "slh-dsa"
))]

use crypto_core::{CryptoError, SignatureOperation};

use crate::operations::OperationError;

#[cfg(any(
    feature = "ed25519",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "secp256k1",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "slh-dsa"
))]
pub(crate) fn crypto_error_from_operation_error(
    _operation: SignatureOperation,
    error: OperationError,
) -> CryptoError {
    error
}

#[cfg(feature = "slh-dsa")]
pub(crate) fn crypto_error_from_length_overflow(_operation: SignatureOperation) -> CryptoError {
    crypto_core::CryptoError::PRIMITIVE_INVALID_LENGTH
}

#[cfg(feature = "secp256k1")]
pub(crate) fn crypto_error_from_bip340_operation_error(
    _operation: SignatureOperation,
    error: OperationError,
) -> CryptoError {
    error
}

#[cfg(feature = "rsa")]
pub(crate) fn crypto_error_from_rsa_operation_error(
    _operation: SignatureOperation,
    error: OperationError,
) -> CryptoError {
    error
}
