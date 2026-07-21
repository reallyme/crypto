// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_return)]

use crate::traits::SignatureAlgorithm;
use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// NIST P-521 (secp521r1) signature adapter.
pub struct P521Algo;

impl SignatureAlgorithm for P521Algo {
    const ALG: Algorithm = Algorithm::P521;

    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_p521::generate_p521_keypair(),
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
                <&[u8; 66]>::try_from(secret).map_err(|_| AlgorithmError::InvalidKey(Self::ALG))?;
            return crypto_p521::generate_p521_keypair_from_secret_key(secret_key)
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
            return crypto_p521::sign_p521_der_prehash(secret, msg).map_err(AlgorithmError::from);
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
            return crypto_p521::verify_p521_der_prehash(sig, msg, public)
                .map_err(|error| crate::algorithms::map_verify_error(Self::ALG, error));
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (public, msg, sig);
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }
}

impl P521Algo {
    /// Derive the P-521 ECDH shared secret; the returned value zeroizes on
    /// drop and must be passed through a protocol KDF before key use.
    pub fn derive_shared_secret(
        secret_key: &[u8],
        public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_p521::derive_p521_shared_secret(secret_key, public_key)
                .map_err(AlgorithmError::from);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (secret_key, public_key);
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }
}
