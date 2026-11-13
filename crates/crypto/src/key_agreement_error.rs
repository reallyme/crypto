// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(
    feature = "x25519",
    feature = "p256",
    feature = "p384",
    feature = "p521"
))]

use crypto_core::CryptoError;

use crate::operations::OperationError;

#[cfg(feature = "x25519")]
pub(crate) fn crypto_error_from_key_generation_operation_error(
    error: OperationError,
) -> CryptoError {
    error
}

pub(crate) fn crypto_error_from_derive_shared_secret_operation_error(
    error: OperationError,
) -> CryptoError {
    error
}
