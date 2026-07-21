// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{AeadFailureKind, CryptoError};

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};

pub(super) fn map_aead_error(error: CryptoError) -> OperationError {
    match error {
        CryptoError::InvalidKey | CryptoError::InvalidAeadKeyLength { .. } => {
            OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            }
        }
        CryptoError::InvalidAeadNonceLength { .. }
        | CryptoError::InvalidCiphertextLength { .. } => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        },
        CryptoError::AeadEncrypt { kind, .. } | CryptoError::AeadDecrypt { kind, .. } => {
            map_aead_failure_kind(kind)
        }
        CryptoError::Unsupported => OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        },
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}

fn map_aead_failure_kind(kind: AeadFailureKind) -> OperationError {
    match kind {
        AeadFailureKind::InvalidKeyMaterial => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        },
        AeadFailureKind::LengthOverflow => OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        },
        AeadFailureKind::ShortCiphertext => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        },
        AeadFailureKind::InvalidOutputLength => OperationError::Backend {
            reason: BackendErrorReason::InvalidOutput,
        },
        AeadFailureKind::AuthenticationFailed => OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        },
        AeadFailureKind::BackendFailure => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}
