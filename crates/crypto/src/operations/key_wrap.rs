// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic owner for AES-KW wrap and unwrap operations.

use crypto_core::KeyWrapAlgorithm;

use super::OperationError;
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
    #[cfg(any(feature = "native", feature = "wasm"))]
    match algorithm {
        KeyWrapAlgorithm::Aes128Kw => {
            let kek = crypto_aes_kw::Aes128KwKek::from_slice(kek)?;
            crypto_aes_kw::wrap_key_aes128(&kek, key_data)
        }
        KeyWrapAlgorithm::Aes192Kw => {
            let kek = crypto_aes_kw::Aes192KwKek::from_slice(kek)?;
            crypto_aes_kw::wrap_key_aes192(&kek, key_data)
        }
        KeyWrapAlgorithm::Aes256Kw => {
            let kek = crypto_aes_kw::Aes256KwKek::from_slice(kek)?;
            crypto_aes_kw::wrap_key_aes256(&kek, key_data)
        }
        _ => Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }

    #[cfg(not(any(feature = "native", feature = "wasm")))]
    {
        let _ = (algorithm, kek, key_data);
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
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
    #[cfg(any(feature = "native", feature = "wasm"))]
    match algorithm {
        KeyWrapAlgorithm::Aes128Kw => {
            let kek = crypto_aes_kw::Aes128KwKek::from_slice(kek)?;
            crypto_aes_kw::unwrap_key_aes128(&kek, wrapped_key)
        }
        KeyWrapAlgorithm::Aes192Kw => {
            let kek = crypto_aes_kw::Aes192KwKek::from_slice(kek)?;
            crypto_aes_kw::unwrap_key_aes192(&kek, wrapped_key)
        }
        KeyWrapAlgorithm::Aes256Kw => {
            let kek = crypto_aes_kw::Aes256KwKek::from_slice(kek)?;
            crypto_aes_kw::unwrap_key_aes256(&kek, wrapped_key)
        }
        _ => Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }

    #[cfg(not(any(feature = "native", feature = "wasm")))]
    {
        let _ = (algorithm, kek, wrapped_key);
        Err(crypto_core::CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}
