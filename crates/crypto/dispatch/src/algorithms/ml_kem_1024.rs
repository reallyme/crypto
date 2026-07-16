// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_return)]
use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// ML-KEM-1024 algorithm adapter.
///
/// This adapter provides key generation and KEM operations.
/// It does NOT implement SignatureAlgorithm.
pub struct MlKem1024Algo;

impl MlKem1024Algo {
    /// The algorithm selector this adapter implements.
    pub const ALG: Algorithm = Algorithm::MlKem1024;

    /// Generate an ML-KEM-1024 keypair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_ml_kem_1024::generate_ml_kem_1024_keypair(),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    /// Encapsulate using the public key.
    ///
    /// Returns (shared_secret, ciphertext); the shared secret zeroizes on
    /// drop.
    pub fn encapsulate(public_key: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            let (ct, ss) = crypto_ml_kem_1024::ml_kem_1024_encapsulate(public_key)
                .map_err(AlgorithmError::from)?;
            return Ok((ss, ct));
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = public_key;
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    /// Decapsulate using the secret key.
    ///
    /// Returns shared_secret; it zeroizes on drop.
    pub fn decapsulate(
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_ml_kem_1024::ml_kem_1024_decapsulate(ciphertext, secret_key)
                .map_err(AlgorithmError::from);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (ciphertext, secret_key);
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }
}
