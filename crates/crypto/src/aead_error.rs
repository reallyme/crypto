// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(
    feature = "dispatch",
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]

use crypto_core::{AeadAlgorithm, AeadBackend, AeadFailureKind, CryptoError};

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};

const AES_128_GCM_KEY_LEN: usize = 16;
const AES_192_GCM_KEY_LEN: usize = 24;
const AEAD_256_BIT_KEY_LEN: usize = 32;
const STANDARD_AEAD_NONCE_LEN: usize = 12;
const XCHACHA20_POLY1305_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadOperation {
    Seal,
    Open,
}

pub(crate) fn crypto_error_from_operation_error(
    algorithm: AeadAlgorithm,
    operation: AeadOperation,
    error: OperationError,
    key_len: usize,
    nonce_len: usize,
    input_len: usize,
) -> CryptoError {
    match error {
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        } => CryptoError::InvalidAeadKeyLength {
            expected: key_length(algorithm),
            actual: key_len,
        },
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        } if nonce_len != nonce_length(algorithm) => CryptoError::InvalidAeadNonceLength {
            expected: nonce_length(algorithm),
            actual: nonce_len,
        },
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        } if operation == AeadOperation::Open => CryptoError::InvalidCiphertextLength {
            minimum: tag_length(algorithm),
            actual: input_len,
        },
        OperationError::Primitive {
            reason: PrimitiveErrorReason::LengthOverflow,
        } => aead_failure(operation, AeadFailureKind::LengthOverflow),
        OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        } => aead_failure(AeadOperation::Open, AeadFailureKind::AuthenticationFailed),
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        } => CryptoError::Unsupported,
        OperationError::Backend {
            reason: BackendErrorReason::InvalidOutput,
        } => aead_failure(operation, AeadFailureKind::InvalidOutputLength),
        _ => aead_failure(operation, AeadFailureKind::BackendFailure),
    }
}

#[cfg(any(
    feature = "aes",
    feature = "aes-gcm-siv",
    feature = "chacha20-poly1305"
))]
pub(crate) fn invalid_output_error(operation: AeadOperation) -> CryptoError {
    aead_failure(operation, AeadFailureKind::InvalidOutputLength)
}

pub(crate) fn current_backend() -> AeadBackend {
    #[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
    {
        AeadBackend::Wasm
    }

    #[cfg(not(all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))))]
    {
        AeadBackend::Native
    }
}

fn aead_failure(operation: AeadOperation, kind: AeadFailureKind) -> CryptoError {
    match operation {
        AeadOperation::Seal => CryptoError::AeadEncrypt {
            backend: current_backend(),
            kind,
        },
        AeadOperation::Open => CryptoError::AeadDecrypt {
            backend: current_backend(),
            kind,
        },
    }
}

fn key_length(algorithm: AeadAlgorithm) -> usize {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => AES_128_GCM_KEY_LEN,
        AeadAlgorithm::Aes192Gcm => AES_192_GCM_KEY_LEN,
        AeadAlgorithm::Aes256Gcm
        | AeadAlgorithm::Aes256GcmSiv
        | AeadAlgorithm::ChaCha20Poly1305
        | AeadAlgorithm::XChaCha20Poly1305 => AEAD_256_BIT_KEY_LEN,
    }
}

fn nonce_length(algorithm: AeadAlgorithm) -> usize {
    match algorithm {
        AeadAlgorithm::Aes128Gcm
        | AeadAlgorithm::Aes192Gcm
        | AeadAlgorithm::Aes256Gcm
        | AeadAlgorithm::Aes256GcmSiv
        | AeadAlgorithm::ChaCha20Poly1305 => STANDARD_AEAD_NONCE_LEN,
        AeadAlgorithm::XChaCha20Poly1305 => XCHACHA20_POLY1305_NONCE_LEN,
    }
}

fn tag_length(_algorithm: AeadAlgorithm) -> usize {
    AEAD_TAG_LEN
}
