// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_return)]
use crate::traits::SignatureAlgorithm;
use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// ML-DSA-65 signature adapter.
pub struct MlDsa65Algo;

impl SignatureAlgorithm for MlDsa65Algo {
    const ALG: Algorithm = Algorithm::MlDsa65;

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_ml_dsa_65::generate_ml_dsa_65_keypair(),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    fn derive_keypair(secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            let seed =
                <&[u8; 32]>::try_from(secret).map_err(|_| AlgorithmError::PRIMITIVE_INVALID_KEY)?;
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_ml_dsa_65::generate_ml_dsa_65_keypair_from_seed(seed),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = secret;
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_ml_dsa_65::sign_ml_dsa_65(secret, msg);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (secret, msg);
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_ml_dsa_65::verify_ml_dsa_65(public, msg, sig)
                .map_err(|error| crate::algorithms::map_verify_error(Self::ALG, error));
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (public, msg, sig);
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }
}
