// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason, ProviderErrorReason};

use crate::status::{CryptoStatus, CRYPTO_INTERNAL_ERROR, CRYPTO_INVALID_KEY};

pub(crate) fn key_agreement_status(error: OperationError) -> CryptoStatus {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        }
        | OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidSharedSecret,
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
