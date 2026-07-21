// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for raw KEM operations.

use crypto_core::Algorithm;
use crypto_dispatch::AlgorithmError;
use zeroize::Zeroizing;

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

/// Raw public/secret keypair returned by a KEM key-management operation.
pub struct KemKeyPair {
    /// Public encapsulation key bytes in the algorithm's canonical encoding.
    pub public_key: Vec<u8>,
    /// Secret decapsulation key or seed bytes. The buffer is wiped when dropped.
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Raw KEM encapsulation output.
pub struct KemEncapsulation {
    /// Ciphertext sent to the decapsulating party.
    pub ciphertext: Vec<u8>,
    /// Shared secret bytes. The buffer is wiped when dropped.
    pub shared_secret: Zeroizing<Vec<u8>>,
}

/// Generates a raw KEM keypair.
pub fn generate_key_pair(algorithm: Algorithm) -> Result<KemKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KemKeyGeneration);
    ensure_kem_algorithm(algorithm)?;
    crypto_dispatch::generate_keypair(algorithm)
        .map(kem_key_pair)
        .map_err(map_dispatch_error)
}

/// Reconstructs a raw KEM keypair from seed material.
pub fn derive_key_pair(
    algorithm: Algorithm,
    secret_key: &[u8],
) -> Result<KemKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KemKeyDerivation);
    ensure_kem_algorithm(algorithm)?;
    crypto_dispatch::derive_keypair(algorithm, secret_key)
        .map(kem_key_pair)
        .map_err(map_dispatch_error)
}

/// Encapsulates to a raw KEM public key.
pub fn encapsulate(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<KemEncapsulation, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KemEncapsulate);
    ensure_kem_algorithm(algorithm)?;
    crypto_dispatch::kem_encapsulate(algorithm, public_key)
        .map(kem_encapsulation)
        .map_err(map_dispatch_error)
}

/// Deterministically encapsulates to a raw KEM public key for conformance.
#[cfg(feature = "test-vectors")]
pub fn encapsulate_derand(
    algorithm: Algorithm,
    public_key: &[u8],
    randomness: &[u8],
) -> Result<KemEncapsulation, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KemEncapsulate);
    ensure_kem_algorithm(algorithm)?;
    match algorithm {
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crypto_ml_kem_512::ml_kem_512_encapsulate_derand(public_key, randomness)
                    .map(kem_encapsulation_from_primitive)
                    .map_err(map_crypto_error)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                let _ = (public_key, randomness);
                Err(unsupported_algorithm())
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crypto_ml_kem_768::ml_kem_768_encapsulate_derand(public_key, randomness)
                    .map(kem_encapsulation_from_primitive)
                    .map_err(map_crypto_error)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                let _ = (public_key, randomness);
                Err(unsupported_algorithm())
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crypto_ml_kem_1024::ml_kem_1024_encapsulate_derand(public_key, randomness)
                    .map(kem_encapsulation_from_primitive)
                    .map_err(map_crypto_error)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                let _ = (public_key, randomness);
                Err(unsupported_algorithm())
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crypto_x_wing::x_wing_768_encapsulate_derand(public_key, randomness)
                    .map(kem_encapsulation_from_primitive)
                    .map_err(map_crypto_error)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                let _ = (public_key, randomness);
                Err(unsupported_algorithm())
            }
        }
        _ => Err(unsupported_algorithm()),
    }
}

/// Decapsulates a raw KEM ciphertext.
pub fn decapsulate(
    algorithm: Algorithm,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::KemDecapsulate);
    ensure_kem_algorithm(algorithm)?;
    crypto_dispatch::kem_decapsulate(algorithm, ciphertext, secret_key).map_err(map_dispatch_error)
}

/// Supports ML-KEM and the standard X-Wing KEM.
pub fn is_kem_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 | Algorithm::XWing768
    )
}

fn ensure_kem_algorithm(algorithm: Algorithm) -> Result<(), OperationError> {
    if is_kem_algorithm(algorithm) {
        Ok(())
    } else {
        Err(unsupported_algorithm())
    }
}

fn kem_key_pair((public_key, secret_key): (Vec<u8>, Zeroizing<Vec<u8>>)) -> KemKeyPair {
    KemKeyPair {
        public_key,
        secret_key,
    }
}

fn kem_encapsulation(
    (shared_secret, ciphertext): (Zeroizing<Vec<u8>>, Vec<u8>),
) -> KemEncapsulation {
    KemEncapsulation {
        ciphertext,
        shared_secret,
    }
}

#[cfg(feature = "test-vectors")]
fn kem_encapsulation_from_primitive(
    (ciphertext, shared_secret): (Vec<u8>, Zeroizing<Vec<u8>>),
) -> KemEncapsulation {
    KemEncapsulation {
        ciphertext,
        shared_secret,
    }
}

fn unsupported_algorithm() -> OperationError {
    OperationError::Provider {
        reason: ProviderErrorReason::UnsupportedAlgorithm,
    }
}

fn map_dispatch_error(error: AlgorithmError) -> OperationError {
    match error {
        AlgorithmError::UnsupportedAlgorithm(_)
        | AlgorithmError::UnsupportedAeadAlgorithm(_)
        | AlgorithmError::UnsupportedHashAlgorithm(_)
        | AlgorithmError::UnsupportedMacAlgorithm(_) => unsupported_algorithm(),
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
        crypto_core::CryptoError::InvalidCiphertextLength { .. } => OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidLength,
        },
        crypto_core::CryptoError::KemFailure { kind } => match kind {
            crypto_core::KemFailureKind::KeyGenerationFailed => OperationError::Backend {
                reason: BackendErrorReason::Internal,
            },
            crypto_core::KemFailureKind::EncapsulateFailed => OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            },
            crypto_core::KemFailureKind::DecapsulateFailed => OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            },
            _ => OperationError::Backend {
                reason: BackendErrorReason::Internal,
            },
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
        crypto_core::CryptoError::Unsupported => unsupported_algorithm(),
        _ => OperationError::Backend {
            reason: BackendErrorReason::Internal,
        },
    }
}
