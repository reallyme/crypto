// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::AlgorithmError;
use crypto_core::Algorithm;

/// A compressed SEC1 prefix and length do not establish curve membership.
/// Parse the point before a multikey identifier can be issued or trusted.
pub(crate) fn validate_compressed_public_key(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<(), AlgorithmError> {
    match algorithm {
        Algorithm::P256 => {
            #[cfg(all(feature = "p256", any(feature = "native", feature = "wasm")))]
            {
                crypto_p256::decompress_public_key(public_key)
                    .map(|_| ())
                    .map_err(|_| AlgorithmError::InvalidKey(algorithm))
            }
            #[cfg(not(all(feature = "p256", any(feature = "native", feature = "wasm"))))]
            {
                let _ = public_key;
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::P384 => {
            #[cfg(all(feature = "p384", any(feature = "native", feature = "wasm")))]
            {
                crypto_p384::decompress_public_key(public_key)
                    .map(|_| ())
                    .map_err(|_| AlgorithmError::InvalidKey(algorithm))
            }
            #[cfg(not(all(feature = "p384", any(feature = "native", feature = "wasm"))))]
            {
                let _ = public_key;
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::P521 => {
            #[cfg(all(feature = "p521", any(feature = "native", feature = "wasm")))]
            {
                crypto_p521::decompress_public_key(public_key)
                    .map(|_| ())
                    .map_err(|_| AlgorithmError::InvalidKey(algorithm))
            }
            #[cfg(not(all(feature = "p521", any(feature = "native", feature = "wasm"))))]
            {
                let _ = public_key;
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(all(feature = "secp256k1", any(feature = "native", feature = "wasm")))]
            {
                crypto_secp256k1::decompress_public_key(public_key)
                    .map(|_| ())
                    .map_err(|_| AlgorithmError::InvalidKey(algorithm))
            }
            #[cfg(not(all(feature = "secp256k1", any(feature = "native", feature = "wasm"))))]
            {
                let _ = public_key;
                Err(AlgorithmError::UnsupportedAlgorithm(algorithm))
            }
        }
        _ => Ok(()),
    }
}
