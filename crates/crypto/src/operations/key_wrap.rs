// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for AES-KW wrap and unwrap operations.

use crypto_core::{CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind};

use super::{BackendErrorReason, OperationError, PrimitiveErrorReason};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Wraps plaintext key material with the selected RFC 3394 AES-KW suite.
///
/// The operation layer owns AES-KW algorithm selection so protobuf, FFI, SDK,
/// and root-facade routes cannot diverge on KEK validation, length policy, or
/// integrity-check error mapping.
pub fn wrap_key(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
    key_data: &[u8],
) -> Result<crypto_aes_kw::AesKwWrappedKey, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyWrap);
    match algorithm {
        KeyWrapAlgorithm::Aes128Kw => {
            let kek = crypto_aes_kw::Aes128KwKek::from_slice(kek).map_err(map_key_wrap_error)?;
            crypto_aes_kw::wrap_key_aes128(&kek, key_data).map_err(map_key_wrap_error)
        }
        KeyWrapAlgorithm::Aes192Kw => {
            let kek = crypto_aes_kw::Aes192KwKek::from_slice(kek).map_err(map_key_wrap_error)?;
            crypto_aes_kw::wrap_key_aes192(&kek, key_data).map_err(map_key_wrap_error)
        }
        KeyWrapAlgorithm::Aes256Kw => {
            let kek = crypto_aes_kw::Aes256KwKek::from_slice(kek).map_err(map_key_wrap_error)?;
            crypto_aes_kw::wrap_key_aes256(&kek, key_data).map_err(map_key_wrap_error)
        }
        _ => Err(OperationError::Provider {
            reason: super::ProviderErrorReason::UnsupportedAlgorithm,
        }),
    }
}

/// Unwraps RFC 3394 AES-KW wrapped key material with the selected suite.
///
/// Returned plaintext remains in the primitive zeroizing owner so adapter
/// boundaries can copy only at their final ABI or wire-format edge.
pub fn unwrap_key(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
    wrapped_key: &[u8],
) -> Result<crypto_aes_kw::AesKwKeyData, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyUnwrap);
    match algorithm {
        KeyWrapAlgorithm::Aes128Kw => {
            let kek = crypto_aes_kw::Aes128KwKek::from_slice(kek).map_err(map_key_wrap_error)?;
            crypto_aes_kw::unwrap_key_aes128(&kek, wrapped_key).map_err(map_key_wrap_error)
        }
        KeyWrapAlgorithm::Aes192Kw => {
            let kek = crypto_aes_kw::Aes192KwKek::from_slice(kek).map_err(map_key_wrap_error)?;
            crypto_aes_kw::unwrap_key_aes192(&kek, wrapped_key).map_err(map_key_wrap_error)
        }
        KeyWrapAlgorithm::Aes256Kw => {
            let kek = crypto_aes_kw::Aes256KwKek::from_slice(kek).map_err(map_key_wrap_error)?;
            crypto_aes_kw::unwrap_key_aes256(&kek, wrapped_key).map_err(map_key_wrap_error)
        }
        _ => Err(OperationError::Provider {
            reason: super::ProviderErrorReason::UnsupportedAlgorithm,
        }),
    }
}

fn map_key_wrap_error(error: CryptoError) -> OperationError {
    match error {
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::InvalidKekLength,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        },
        CryptoError::KeyWrap {
            kind:
                KeyWrapFailureKind::InvalidPlaintextLength | KeyWrapFailureKind::InvalidWrappedLength,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        },
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::LengthOverflow,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        },
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::IntegrityCheckFailed,
            ..
        } => OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        },
        CryptoError::KeyWrap {
            kind: KeyWrapFailureKind::BackendFailure,
            ..
        } => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
        CryptoError::Unsupported => OperationError::Provider {
            reason: super::ProviderErrorReason::UnsupportedAlgorithm,
        },
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}
