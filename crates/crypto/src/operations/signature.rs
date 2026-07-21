// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Semantic owner for raw-key signature operations.

use crypto_core::Algorithm;
use crypto_dispatch::AlgorithmError;
use zeroize::Zeroizing;

use crate::operations::{
    BackendErrorReason, OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use crate::secret_material::{bind_operation_policy, SecretMaterialOperation};

#[cfg(feature = "slh-dsa")]
const SLH_DSA_SEED_COMPONENT_LEN: usize = crypto_slh_dsa::SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN;
#[cfg(feature = "slh-dsa")]
const SLH_DSA_DERIVE_INPUT_LEN: usize = SLH_DSA_SEED_COMPONENT_LEN * 3;

/// Raw public/secret keypair returned by a signature key-management operation.
pub struct SignatureKeyPair {
    /// Public verification key bytes in the algorithm's canonical encoding.
    pub public_key: Vec<u8>,
    /// Secret signing key bytes. The buffer is wiped when dropped.
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Generates a raw keypair for a supported raw-key signature algorithm.
pub fn generate_key_pair(algorithm: Algorithm) -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyGeneration);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return generate_slh_dsa_sha2_128s_key_pair();
    }
    crypto_dispatch::generate_keypair(algorithm)
        .map(signature_key_pair)
        .map_err(map_dispatch_error)
}

/// Reconstructs a raw keypair from seed or scalar material.
pub fn derive_key_pair(
    algorithm: Algorithm,
    secret_key: &[u8],
) -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyDerivation);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return derive_slh_dsa_sha2_128s_key_pair(secret_key);
    }
    crypto_dispatch::derive_keypair(algorithm, secret_key)
        .map(signature_key_pair)
        .map_err(map_dispatch_error)
}

/// Signs `message` with raw secret material.
pub fn sign(
    algorithm: Algorithm,
    secret_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureSign);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return sign_slh_dsa_sha2_128s(secret_key, message);
    }
    crypto_dispatch::sign(algorithm, secret_key, message).map_err(map_dispatch_error)
}

/// Verifies `signature` against `message` and `public_key`.
pub fn verify(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    ensure_supported_signature_algorithm(algorithm)?;
    if algorithm == Algorithm::SlhDsaSha2_128s {
        return verify_slh_dsa_sha2_128s(public_key, message, signature);
    }
    crypto_dispatch::verify(algorithm, public_key, message, signature).map_err(map_dispatch_error)
}

/// Generates a BIP-340 keypair with an x-only public key.
pub fn generate_bip340_key_pair() -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyGeneration);
    #[cfg(feature = "secp256k1")]
    {
        let key_pair = generate_key_pair(Algorithm::Secp256k1)?;
        let public_key = derive_bip340_public_key(&key_pair.secret_key)?;
        Ok(SignatureKeyPair {
            public_key,
            secret_key: key_pair.secret_key,
        })
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

/// Reconstructs a BIP-340 keypair from a validated secp256k1 secret scalar.
pub fn derive_bip340_key_pair(secret_key: &[u8]) -> Result<SignatureKeyPair, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyDerivation);
    let public_key = derive_bip340_public_key(secret_key)?;
    Ok(SignatureKeyPair {
        public_key,
        secret_key: Zeroizing::new(secret_key.to_vec()),
    })
}

/// Derives a BIP-340 x-only public key from a secp256k1 secret scalar.
pub fn derive_bip340_public_key(secret_key: &[u8]) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureKeyDerivation);
    #[cfg(feature = "secp256k1")]
    {
        crypto_secp256k1::derive_bip340_schnorr_public_key(secret_key).map_err(map_crypto_error)
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = secret_key;
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

/// Signs a 32-byte BIP-340 message with explicit 32-byte auxiliary randomness.
pub fn sign_bip340(
    secret_key: &[u8],
    message32: &[u8],
    aux_rand32: &[u8],
) -> Result<Vec<u8>, OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureSign);
    #[cfg(feature = "secp256k1")]
    {
        crypto_secp256k1::sign_bip340_schnorr(secret_key, message32, aux_rand32)
            .map_err(map_crypto_error)
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = (secret_key, message32, aux_rand32);
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

/// Verifies a BIP-340 Schnorr signature over a 32-byte message.
pub fn verify_bip340(
    signature: &[u8],
    message32: &[u8],
    public_key_xonly: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    #[cfg(feature = "secp256k1")]
    {
        crypto_secp256k1::verify_bip340_schnorr(signature, message32, public_key_xonly)
            .map_err(map_crypto_error)
    }

    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = (signature, message32, public_key_xonly);
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

/// Verifies an RSASSA-PKCS1-v1_5 signature.
#[cfg(feature = "rsa")]
pub fn verify_rsa_pkcs1v15(
    public_key_der: &[u8],
    encoding: crypto_rsa::RsaPublicKeyDerEncoding,
    hash: crypto_rsa::RsaHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    crypto_rsa::verify_rsa_pkcs1v15(public_key_der, encoding, hash, message, signature)
        .map_err(map_crypto_error)
}

/// Verifies an RSASSA-PSS signature with explicit message and MGF1 hashes.
#[cfg(feature = "rsa")]
pub fn verify_rsa_pss(
    public_key_der: &[u8],
    encoding: crypto_rsa::RsaPublicKeyDerEncoding,
    params: crypto_rsa::RsaPssParams,
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    let _policy = bind_operation_policy(SecretMaterialOperation::SignatureVerify);
    crypto_rsa::verify_rsa_pss(public_key_der, encoding, params, message, signature)
        .map_err(map_crypto_error)
}

fn is_supported_signature_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ed25519
            | Algorithm::P256
            | Algorithm::P384
            | Algorithm::P521
            | Algorithm::Secp256k1
            | Algorithm::MlDsa44
            | Algorithm::MlDsa65
            | Algorithm::MlDsa87
            | Algorithm::SlhDsaSha2_128s
    )
}

fn ensure_supported_signature_algorithm(algorithm: Algorithm) -> Result<(), OperationError> {
    if is_supported_signature_algorithm(algorithm) {
        Ok(())
    } else {
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

fn generate_slh_dsa_sha2_128s_key_pair() -> Result<SignatureKeyPair, OperationError> {
    #[cfg(feature = "slh-dsa")]
    {
        crypto_slh_dsa::generate_slh_dsa_sha2_128s_keypair()
            .map(signature_key_pair)
            .map_err(map_crypto_error)
    }

    #[cfg(not(feature = "slh-dsa"))]
    {
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

fn derive_slh_dsa_sha2_128s_key_pair(
    secret_key: &[u8],
) -> Result<SignatureKeyPair, OperationError> {
    #[cfg(feature = "slh-dsa")]
    {
        if secret_key.len() != SLH_DSA_DERIVE_INPUT_LEN {
            return Err(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            });
        }
        let (sk_seed, rest) = secret_key.split_at(SLH_DSA_SEED_COMPONENT_LEN);
        let (sk_prf, pk_seed) = rest.split_at(SLH_DSA_SEED_COMPONENT_LEN);
        crypto_slh_dsa::derive_slh_dsa_sha2_128s_keypair(sk_seed, sk_prf, pk_seed)
            .map(signature_key_pair)
            .map_err(map_crypto_error)
    }

    #[cfg(not(feature = "slh-dsa"))]
    {
        let _ = secret_key;
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

fn sign_slh_dsa_sha2_128s(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, OperationError> {
    #[cfg(feature = "slh-dsa")]
    {
        crypto_slh_dsa::sign_slh_dsa_sha2_128s(secret_key, message).map_err(map_crypto_error)
    }

    #[cfg(not(feature = "slh-dsa"))]
    {
        let _ = (secret_key, message);
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

fn verify_slh_dsa_sha2_128s(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OperationError> {
    #[cfg(feature = "slh-dsa")]
    {
        crypto_slh_dsa::verify_slh_dsa_sha2_128s(public_key, message, signature)
            .map_err(map_crypto_error)
    }

    #[cfg(not(feature = "slh-dsa"))]
    {
        let _ = (public_key, message, signature);
        Err(OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm,
        })
    }
}

fn signature_key_pair((public_key, secret_key): (Vec<u8>, Zeroizing<Vec<u8>>)) -> SignatureKeyPair {
    SignatureKeyPair {
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
        crypto_core::CryptoError::Signature { kind, .. } => match kind {
            crypto_core::SignatureFailureKind::InvalidPrivateKey
            | crypto_core::SignatureFailureKind::InvalidPublicKey => OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            },
            crypto_core::SignatureFailureKind::InvalidSignature => OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            },
            crypto_core::SignatureFailureKind::InvalidMessage => OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidLength,
            },
            crypto_core::SignatureFailureKind::KeyGenerationFailed => OperationError::Backend {
                reason: BackendErrorReason::Internal,
            },
            crypto_core::SignatureFailureKind::SecureEnclaveUnavailable => {
                OperationError::Provider {
                    reason: ProviderErrorReason::HardwareUnavailable,
                }
            }
            crypto_core::SignatureFailureKind::SecureEnclaveRejectedKey => {
                OperationError::Provider {
                    reason: ProviderErrorReason::HardwareRejectedKey,
                }
            }
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
