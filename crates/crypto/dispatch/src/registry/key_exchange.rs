// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::provider::ProviderOperation;
use crate::AlgorithmError;
use crypto_core::Algorithm;

/// Derive a Diffie–Hellman shared secret. The returned secret zeroizes on
/// drop.
pub fn derive_shared_secret(
    alg: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::DeriveSharedSecret, alg)?;
    #[cfg(not(any(
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "x25519"
    )))]
    let _ = (secret_key, public_key);

    match alg {
        Algorithm::P256 => {
            #[cfg(feature = "p256")]
            {
                crate::algorithms::p256::P256Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "p256"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P384 => {
            #[cfg(feature = "p384")]
            {
                crate::algorithms::p384::P384Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "p384"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::P521 => {
            #[cfg(feature = "p521")]
            {
                crate::algorithms::p521::P521Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "p521"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::X25519 => {
            #[cfg(feature = "x25519")]
            {
                crate::algorithms::x25519::X25519Algo::derive_shared_secret(secret_key, public_key)
            }
            #[cfg(not(feature = "x25519"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

//
// -----------------------------------------------------------------------------
// POST-QUANTUM KEM
// -----------------------------------------------------------------------------

/// Returns (shared_secret, ciphertext); the shared secret zeroizes on drop.
pub fn kem_encapsulate(
    alg: Algorithm,
    public_key: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::KemEncapsulate, alg)?;
    #[cfg(not(any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )))]
    let _ = public_key;

    match alg {
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::encapsulate(public_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}

/// Decapsulate a KEM ciphertext. The returned shared secret zeroizes on drop.
pub fn kem_decapsulate(
    alg: Algorithm,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
    let _decision = crate::provider::require_provider(ProviderOperation::KemDecapsulate, alg)?;
    #[cfg(not(any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )))]
    let _ = (ciphertext, secret_key);

    match alg {
        Algorithm::MlKem512 => {
            #[cfg(feature = "ml-kem-512")]
            {
                crate::algorithms::ml_kem_512::MlKem512Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "ml-kem-512"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem768 => {
            #[cfg(feature = "ml-kem-768")]
            {
                crate::algorithms::ml_kem_768::MlKem768Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "ml-kem-768"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::MlKem1024 => {
            #[cfg(feature = "ml-kem-1024")]
            {
                crate::algorithms::ml_kem_1024::MlKem1024Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "ml-kem-1024"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        Algorithm::XWing768 => {
            #[cfg(feature = "x-wing")]
            {
                crate::algorithms::x_wing::XWing768Algo::decapsulate(ciphertext, secret_key)
            }
            #[cfg(not(feature = "x-wing"))]
            {
                Err(AlgorithmError::UnsupportedAlgorithm(alg))
            }
        }
        _ => Err(AlgorithmError::UnsupportedAlgorithm(alg)),
    }
}
