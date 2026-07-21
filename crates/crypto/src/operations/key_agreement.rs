// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for raw key-agreement operations.

use crypto_core::Algorithm;
use crypto_dispatch::AlgorithmError;
use zeroize::Zeroizing;

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Raw public/secret keypair returned by a key-agreement key-management operation.
pub struct KeyAgreementKeyPair {
    /// Public key bytes in the algorithm's canonical key-agreement encoding.
    pub public_key: Vec<u8>,
    /// Secret key or seed bytes. The buffer is wiped when dropped.
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Generates a raw key-agreement keypair.
pub fn generate_key_pair(algorithm: Algorithm) -> Result<KeyAgreementKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyAgreementKeyGeneration);
    ensure_key_agreement_algorithm(algorithm)?;
    crypto_dispatch::generate_keypair(algorithm)
        .map(key_agreement_key_pair)
        .map_err(map_dispatch_error)
}

/// Reconstructs a raw key-agreement keypair from seed or scalar material.
pub fn derive_key_pair(
    algorithm: Algorithm,
    secret_key: &[u8],
) -> Result<KeyAgreementKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyAgreementKeyDerivation);
    ensure_key_agreement_algorithm(algorithm)?;
    crypto_dispatch::derive_keypair(algorithm, secret_key)
        .map(key_agreement_key_pair)
        .map_err(map_dispatch_error)
}

/// Derives the raw Diffie-Hellman shared secret.
///
/// This operation intentionally returns the primitive shared-secret output
/// without applying a KDF. Protocol layers must bind algorithm, transcript,
/// party, and application context in their own extract/expand step.
pub fn derive_shared_secret(
    algorithm: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KeyAgreementSharedSecret);
    ensure_key_agreement_algorithm(algorithm)?;
    crypto_dispatch::derive_shared_secret(algorithm, secret_key, public_key)
        .map_err(map_dispatch_error)
}

/// Supports X25519 and NIST-curve raw key agreement.
pub fn is_key_agreement_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::X25519 | Algorithm::P256 | Algorithm::P384 | Algorithm::P521
    )
}

fn ensure_key_agreement_algorithm(algorithm: Algorithm) -> Result<(), OperationError> {
    if is_key_agreement_algorithm(algorithm) {
        Ok(())
    } else {
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

fn key_agreement_key_pair(
    (public_key, secret_key): (Vec<u8>, Zeroizing<Vec<u8>>),
) -> KeyAgreementKeyPair {
    KeyAgreementKeyPair {
        public_key,
        secret_key,
    }
}

fn map_dispatch_error(error: AlgorithmError) -> OperationError {
    match error {
        AlgorithmError::UnsupportedAlgorithm(_)
        | AlgorithmError::UnsupportedAeadAlgorithm(_)
        | AlgorithmError::UnsupportedHashAlgorithm(_)
        | AlgorithmError::UnsupportedMacAlgorithm(_) => OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        },
        AlgorithmError::InvalidKey(_) => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        },
        AlgorithmError::SignatureInvalid(_) => OperationError::Primitive {
            reason: PrimitiveErrorReason::VerificationFailed,
        },
        AlgorithmError::Crypto(error) => map_crypto_error(error),
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}

fn map_crypto_error(error: crypto_core::CryptoError) -> OperationError {
    match error {
        crypto_core::CryptoError::InvalidKey => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey,
        },
        crypto_core::CryptoError::KeyAgreementFailure { kind } => match kind {
            crypto_core::KeyAgreementFailureKind::DeriveSharedSecretFailed => {
                OperationError::Primitive {
                    reason: PrimitiveErrorReason::InvalidSharedSecret,
                }
            }
            crypto_core::KeyAgreementFailureKind::KeyGenerationFailed => OperationError::Backend {
                reason: BackendErrorReason::Internal,
            },
            _ => OperationError::Backend {
                reason: BackendErrorReason::Internal,
            },
        },
        crypto_core::CryptoError::Unsupported => OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        },
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}
