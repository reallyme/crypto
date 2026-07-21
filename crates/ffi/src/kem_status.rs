// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

use crate::status::{
    CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_CIPHERTEXT, CRYPTO_INVALID_KEY,
};

pub(crate) fn kem_key_management_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        }
        | OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INVALID_KEY,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}

pub(crate) fn kem_encapsulation_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        }
        | OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidSharedSecret,
        }
        | OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}

pub(crate) fn kem_decapsulation_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        }
        | OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CRYPTO_INVALID_KEY,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => CRYPTO_INVALID_CIPHERTEXT,
        OperationError::Backend { .. }
        | OperationError::Provider { .. }
        | OperationError::Primitive { .. }
        | _ => CRYPTO_INTERNAL_ERROR,
    }
}
