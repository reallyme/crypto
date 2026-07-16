// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::AlgorithmError;
use crypto_core::Algorithm;
use zeroize::Zeroizing;

/// X-Wing ML-KEM-768 hybrid KEM adapter.
pub struct XWing768Algo;

/// X-Wing ML-KEM-1024 hybrid KEM adapter.
pub struct XWing1024Algo;

impl XWing768Algo {
    /// The algorithm selector this adapter implements.
    pub const ALG: Algorithm = Algorithm::XWing768;

    /// Generate an X-Wing-768 keypair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        crypto_x_wing::generate_x_wing_768_keypair().map_err(AlgorithmError::from)
    }

    /// Encapsulate using the public key.
    pub fn encapsulate(public_key: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AlgorithmError> {
        let (ciphertext, shared_secret) =
            crypto_x_wing::x_wing_768_encapsulate(public_key).map_err(AlgorithmError::from)?;
        Ok((shared_secret, ciphertext))
    }

    /// Decapsulate using the secret key.
    pub fn decapsulate(
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        crypto_x_wing::x_wing_768_decapsulate(ciphertext, secret_key).map_err(AlgorithmError::from)
    }
}

impl XWing1024Algo {
    /// The algorithm selector this adapter implements.
    pub const ALG: Algorithm = Algorithm::XWing1024;

    /// Generate an X-Wing-1024 keypair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        crypto_x_wing::generate_x_wing_1024_keypair().map_err(AlgorithmError::from)
    }

    /// Encapsulate using the public key.
    pub fn encapsulate(public_key: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AlgorithmError> {
        let (ciphertext, shared_secret) =
            crypto_x_wing::x_wing_1024_encapsulate(public_key).map_err(AlgorithmError::from)?;
        Ok((shared_secret, ciphertext))
    }

    /// Decapsulate using the secret key.
    pub fn decapsulate(
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AlgorithmError> {
        crypto_x_wing::x_wing_1024_decapsulate(ciphertext, secret_key).map_err(AlgorithmError::from)
    }
}
