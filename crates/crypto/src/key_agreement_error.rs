// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(
    feature = "x25519",
    feature = "p256",
    feature = "p384",
    feature = "p521"
))]

use crypto_core::{CryptoError, KeyAgreementFailureKind};

use crate::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

#[cfg(feature = "x25519")]
pub(crate) fn crypto_error_from_key_generation_operation_error(
    error: OperationError,
) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CryptoError::InvalidKey,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. } => key_generation_failed(),
    }
}

pub(crate) fn crypto_error_from_derive_shared_secret_operation_error(
    error: OperationError,
) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CryptoError::InvalidKey,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidSharedSecret,
        } => derive_shared_secret_failed(),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. } => derive_shared_secret_failed(),
    }
}

fn derive_shared_secret_failed() -> CryptoError {
    CryptoError::KeyAgreementFailure {
        kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
    }
}

#[cfg(feature = "x25519")]
fn key_generation_failed() -> CryptoError {
    CryptoError::KeyAgreementFailure {
        kind: KeyAgreementFailureKind::KeyGenerationFailed,
    }
}
