// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_return)]

use crate::traits::SignatureAlgorithm;
use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// Ed25519 signature adapter.
pub struct Ed25519Algo;

impl SignatureAlgorithm for Ed25519Algo {
    const ALG: Algorithm = Algorithm::Ed25519;

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_ed25519::generate_ed25519_keypair();
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
                crypto_ed25519::generate_ed25519_keypair_from_seed(seed),
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
            return crypto_ed25519::sign_ed25519(secret, msg);
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
            return crypto_ed25519::verify_ed25519(public, msg, sig)
                .map_err(|error| crate::algorithms::map_verify_error(Self::ALG, error));
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (public, msg, sig);
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }
}
