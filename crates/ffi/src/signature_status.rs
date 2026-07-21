// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};

use crate::status::{
    CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_KEY, CRYPTO_INVALID_SIGNATURE,
};

pub(crate) fn key_management_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INVALID_KEY,
        OperationError::Backend {
            reason: BackendErrorReason::InvalidOutput,
        }
        | OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}

pub(crate) fn sign_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INVALID_KEY,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}

pub(crate) fn verify_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => CRYPTO_INVALID_SIGNATURE,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INVALID_KEY,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}
