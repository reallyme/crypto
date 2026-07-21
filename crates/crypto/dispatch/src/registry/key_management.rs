// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::provider::ProviderOperation;
#[cfg(any(
    feature = "ed25519",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "secp256k1",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87"
))]
use crate::traits::SignatureAlgorithm;
use crate::AlgorithmError;
use crypto_core::Algorithm;

/// Generate a raw keypair for the given algorithm.
///
/// This is supported for:
/// - signature algorithms
/// - key agreement algorithms
/// - KEM algorithms
///
/// Returns (public_key, secret_key); the secret half zeroizes on drop.
pub fn generate_keypair(alg: Algorithm) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::GenerateKeyPair, alg)?;
    match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::generate_keypair()
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::generate_keypair()
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::generate_keypair()
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::generate_keypair()
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::generate_keypair()
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::SlhDsaSha2_128s => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                crate::algorithms::x25519::X25519Algo::generate_keypair()
            }
            #[cfg(not(feature = "x25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::generate_keypair()
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::generate_keypair()
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
    }
}

/// Reconstruct a raw keypair for the given algorithm from existing secret
/// material.
///
/// The selected algorithm defines the accepted secret shape. Ed25519, X25519,
/// ML-DSA, ML-KEM, and X-Wing use seed-form secret keys; NIST and secp256k1
/// curve algorithms use validated private scalars. This is import, not
/// password-based key generation.
pub fn derive_keypair(
    alg: Algorithm,
    secret: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::DeriveKeyPair, alg)?;
    match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "p256"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "p384"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "p521"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::SlhDsaSha2_128s => {
            let _ = secret;
            Err(AlgorithmError::UnsupportedAlgorithm(alg))
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                crate::algorithms::x25519::X25519Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "x25519"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::derive_keypair(secret)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                let _ = secret;
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
    }
}
