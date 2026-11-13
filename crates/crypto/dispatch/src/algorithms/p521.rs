// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    fn derive_keypair(secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(feature = "native")]
        {
            let secret_key =
                <&[u8; 66]>::try_from(secret).map_err(|_| AlgorithmError::PRIMITIVE_INVALID_KEY)?;
            return crypto_p521::generate_p521_keypair_from_secret_key(secret_key);
        }

        #[cfg(not(feature = "native"))]
        {
            let _ = secret;
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }

    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_p521::sign_p521_der_prehash(secret, msg);
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
            return crypto_p521::verify_p521_der_prehash(sig, msg, public);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (public, msg, sig);
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
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
            return crypto_p521::derive_p521_shared_secret(secret_key, public_key);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (secret_key, public_key);
            Err(AlgorithmError::PROVIDER_UNSUPPORTED_ALGORITHM)
        }
    }
}
