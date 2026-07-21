// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_return)]
use crate::traits::SignatureAlgorithm;
use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// secp256k1 signature adapter.
pub struct Secp256k1Algo;

impl SignatureAlgorithm for Secp256k1Algo {
    const ALG: Algorithm = Algorithm::Secp256k1;

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_secp256k1::generate_secp256k1_keypair(),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    fn derive_keypair(secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(feature = "native")]
        {
            let secret_key =
                <&[u8; 32]>::try_from(secret).map_err(|_| AlgorithmError::InvalidKey(Self::ALG))?;
            return crypto_secp256k1::generate_secp256k1_keypair_from_secret_key(secret_key)
                .map_err(AlgorithmError::from);
        }

        #[cfg(not(feature = "native"))]
        {
            let _ = secret;
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_secp256k1::sign_secp256k1(secret, msg).map_err(AlgorithmError::from);
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
            return crypto_secp256k1::verify_secp256k1(sig, msg, public)
                .map_err(|error| crate::algorithms::map_verify_error(Self::ALG, error));
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (public, msg, sig);
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }
}
