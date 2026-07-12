// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "sha2", feature = "sha3"))]
use crate::traits::HashDigestAlgorithm;
use crate::AlgorithmError;
use crypto_core::HashAlgorithm;

/// Compute a digest using the selected hash algorithm.
pub fn hash_digest(alg: HashAlgorithm, message: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
    #[cfg(not(any(feature = "sha2", feature = "sha3")))]
    let _ = message;

    match alg {
        HashAlgorithm::Sha2_256 => {
            #[cfg(feature = "sha2")]
            {
                crate::algorithms::sha2_256::Sha2_256Algo::digest(message)
            }
            #[cfg(not(feature = "sha2"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
        HashAlgorithm::Sha2_384 => {
            #[cfg(feature = "sha2")]
            {
                crate::algorithms::sha2::Sha2_384Algo::digest(message)
            }
            #[cfg(not(feature = "sha2"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
        HashAlgorithm::Sha2_512 => {
            #[cfg(feature = "sha2")]
            {
                crate::algorithms::sha2::Sha2_512Algo::digest(message)
            }
            #[cfg(not(feature = "sha2"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
        HashAlgorithm::Sha3_224 => {
            #[cfg(feature = "sha3")]
            {
                crate::algorithms::sha3::Sha3_224Algo::digest(message)
            }
            #[cfg(not(feature = "sha3"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
        HashAlgorithm::Sha3_256 => {
            #[cfg(feature = "sha3")]
            {
                crate::algorithms::sha3_256::Sha3_256Algo::digest(message)
            }
            #[cfg(not(feature = "sha3"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
        HashAlgorithm::Sha3_384 => {
            #[cfg(feature = "sha3")]
            {
                crate::algorithms::sha3::Sha3_384Algo::digest(message)
            }
            #[cfg(not(feature = "sha3"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
        HashAlgorithm::Sha3_512 => {
            #[cfg(feature = "sha3")]
            {
                crate::algorithms::sha3::Sha3_512Algo::digest(message)
            }
            #[cfg(not(feature = "sha3"))]
            {
                Err(AlgorithmError::UnsupportedHashAlgorithm(alg))
            }
        }
    }
}
