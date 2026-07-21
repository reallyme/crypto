// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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

/// Sign `msg` with `secret` under the selected signature algorithm,
/// returning the detached signature bytes.
///
/// The crate README contains the compile-checked signature example so test
/// code remains separate from this production implementation.
pub fn sign(alg: Algorithm, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::Sign, alg)?;
    #[cfg(not(any(
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87"
    )))]
    let _ = (secret, msg);

    match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::sign(secret, msg)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

/// Verify a detached signature.
///
/// Fails closed: a signature that does not verify is an
/// [`AlgorithmError::SignatureInvalid`] error, never a boolean, so a
/// forgotten result check cannot be mistaken for success.
///
/// The crate README contains the compile-checked fail-closed verification
/// example so test code remains separate from this production implementation.
pub fn verify(alg: Algorithm, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::Verify, alg)?;
    #[cfg(not(any(
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87"
    )))]
    let _ = (public, msg, sig);

    match alg {
        Algorithm::Ed25519 => {
            #[cfg(feature = "ed25519")]
            {
                crate::algorithms::ed25519::Ed25519Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ed25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "secp256k1")]
            {
                crate::algorithms::secp256k1::Secp256k1Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "secp256k1"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa44 => {
            #[cfg(feature = "ml-dsa-44")]
            {
                crate::algorithms::ml_dsa_44::MlDsa44Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ml-dsa-44"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa65 => {
            #[cfg(feature = "ml-dsa-65")]
            {
                crate::algorithms::ml_dsa_65::MlDsa65Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ml-dsa-65"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlDsa87 => {
            #[cfg(feature = "ml-dsa-87")]
            {
                crate::algorithms::ml_dsa_87::MlDsa87Algo::verify(public, msg, sig)
            }
            #[cfg(not(feature = "ml-dsa-87"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}
