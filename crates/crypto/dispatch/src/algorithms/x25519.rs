// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_return)]
use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// X25519 algorithm adapter.
///
/// Provides key generation and Diffie–Hellman shared secret derivation.
/// Does NOT implement SignatureAlgorithm.
pub struct X25519Algo;

impl X25519Algo {
    /// The algorithm selector this adapter implements.
    pub const ALG: Algorithm = Algorithm::X25519;

    /// Generate an X25519 keypair; the secret half zeroizes on drop.
    pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_x25519::generate_x25519_keypair(),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    /// Reconstruct an X25519 keypair from existing secret seed material.
    pub fn derive_keypair(secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            let seed =
                <&[u8; 32]>::try_from(secret).map_err(|_| AlgorithmError::InvalidKey(Self::ALG))?;
            return crate::algorithms::KeypairResultExt::into_algorithm_keypair(
                crypto_x25519::generate_x25519_keypair_from_seed(seed),
                Self::ALG,
            );
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = secret;
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }

    /// Derive the X25519 Diffie–Hellman shared secret; it zeroizes on drop.
    pub fn derive_shared_secret(
        secret_key: &[u8],
        public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        #[cfg(any(feature = "native", all(feature = "wasm", target_arch = "wasm32")))]
        {
            return crypto_x25519::derive_x25519_shared_secret(secret_key, public_key)
                .map_err(AlgorithmError::from);
        }

        #[cfg(not(any(feature = "native", all(feature = "wasm", target_arch = "wasm32"))))]
        {
            let _ = (secret_key, public_key);
            Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
        }
    }
}
