// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(any(
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024",
    feature = "x-wing"
))]

use crypto_core::CryptoError;

use crate::operations::OperationError;

pub(crate) fn crypto_error_from_kem_key_generation_operation_error(
    error: OperationError,
) -> CryptoError {
    error
}

pub(crate) fn crypto_error_from_kem_encapsulation_operation_error(
    error: OperationError,
) -> CryptoError {
    error
}

pub(crate) fn crypto_error_from_kem_decapsulation_operation_error(
    error: OperationError,
) -> CryptoError {
    error
}
