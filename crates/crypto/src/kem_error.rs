// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024",
    feature = "x-wing"
))]

use crypto_core::{CryptoError, KemFailureKind, KeyAgreementFailureKind};

use crate::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

pub(crate) fn crypto_error_from_kem_key_generation_operation_error(
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
        | OperationError::Primitive { .. } => kem_failed(KemFailureKind::KeyGenerationFailed),
    }
}

pub(crate) fn crypto_error_from_kem_encapsulation_operation_error(
    error: OperationError,
) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CryptoError::InvalidKey,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidSharedSecret,
        } => key_agreement_failed(),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. } => kem_failed(KemFailureKind::EncapsulateFailed),
    }
}

pub(crate) fn crypto_error_from_kem_decapsulation_operation_error(
    error: OperationError,
) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CryptoError::InvalidKey,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => kem_failed(KemFailureKind::DecapsulateFailed),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. } => kem_failed(KemFailureKind::DecapsulateFailed),
    }
}

fn kem_failed(kind: KemFailureKind) -> CryptoError {
    CryptoError::KemFailure { kind }
}

fn key_agreement_failed() -> CryptoError {
    CryptoError::KeyAgreementFailure {
        kind: KeyAgreementFailureKind::DeriveSharedSecretFailed,
    }
}
