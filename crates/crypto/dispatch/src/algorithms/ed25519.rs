// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
            return crypto_ed25519::generate_ed25519_keypair().map_err(AlgorithmError::from);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    fn derive_keypair(secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            let seed =
                <&[u8; 32]>::try_from(secret).map_err(|_| AlgorithmError::InvalidKey(Self::ALG))?;
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_ed25519::generate_ed25519_keypair_from_seed(seed),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = secret;
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_ed25519::sign_ed25519(secret, msg).map_err(AlgorithmError::from);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (secret, msg);
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
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
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }
}
