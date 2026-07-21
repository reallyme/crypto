// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};

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
use crate::operations::BackendErrorReason;
use crate::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

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
    operation: SignatureOperation,
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
            reason: PrimitiveErrorReason::LengthOverflow,
        } => signature_error(operation, SignatureFailureKind::InvalidSignature),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => signature_error(operation, SignatureFailureKind::InvalidSignature),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Provider {
            reason: ProviderErrorReason::HardwareUnavailable,
        }
        | OperationError::Provider {
            reason: ProviderErrorReason::PlatformUnavailable,
        } => signature_error(operation, SignatureFailureKind::SecureEnclaveUnavailable),
        OperationError::Provider {
            reason: ProviderErrorReason::HardwareRejectedKey,
        } => signature_error(operation, SignatureFailureKind::SecureEnclaveRejectedKey),
        OperationError::Backend {
            reason: BackendErrorReason::InvalidOutput,
        } => signature_error(operation, SignatureFailureKind::BackendFailure),
        OperationError::Backend { .. } | OperationError::Provider { .. } => {
            signature_error(operation, SignatureFailureKind::BackendFailure)
        }
        OperationError::Primitive { .. } => CryptoError::InvalidKey,
    }
}

#[cfg(feature = "slh-dsa")]
pub(crate) fn crypto_error_from_length_overflow(operation: SignatureOperation) -> CryptoError {
    signature_error(operation, SignatureFailureKind::BackendFailure)
}

#[cfg(feature = "secp256k1")]
pub(crate) fn crypto_error_from_bip340_operation_error(
    operation: SignatureOperation,
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
            reason: PrimitiveErrorReason::LengthOverflow,
        } => signature_error(operation, SignatureFailureKind::InvalidMessage),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => signature_error(operation, SignatureFailureKind::InvalidSignature),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. } => {
            signature_error(operation, SignatureFailureKind::BackendFailure)
        }
    }
}

#[cfg(feature = "rsa")]
pub(crate) fn crypto_error_from_rsa_operation_error(
    operation: SignatureOperation,
    error: OperationError,
) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CryptoError::InvalidKey,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => signature_error(operation, SignatureFailureKind::InvalidSignature),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. } => {
            signature_error(operation, SignatureFailureKind::BackendFailure)
        }
    }
}

fn signature_error(operation: SignatureOperation, kind: SignatureFailureKind) -> CryptoError {
    CryptoError::Signature {
        backend: current_backend(),
        operation,
        kind,
    }
}

fn current_backend() -> SignatureBackend {
    #[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
    {
        SignatureBackend::Wasm
    }

    #[cfg(not(all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))))]
    {
        SignatureBackend::Native
    }
}
