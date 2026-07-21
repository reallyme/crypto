// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroizing;

use crate::AlgorithmError;
use crypto_core::Algorithm;

/// Adapter contract for a detached-signature algorithm.
pub trait SignatureAlgorithm {
    /// The algorithm selector this adapter implements.
    const ALG: Algorithm;

    /// Generate a keypair, returning `(public_key, secret_key)`; the secret
    /// zeroizes on drop.
    fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError>;
    /// Reconstruct a keypair from existing secret material.
    ///
    /// Algorithms define the exact secret shape: Ed25519, ML-DSA, and similar
    /// seed-form keys import a seed, while elliptic-curve algorithms import a
    /// private scalar. This path is not password-based key generation.
    fn derive_keypair(secret: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError> {
        let _ = secret;
        Err(AlgorithmError::UnsupportedAlgorithm(Self::ALG))
    }
    /// Sign `msg` with `secret`, returning the detached signature bytes.
    fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, AlgorithmError>;
    /// Verify `sig` over `msg` against `public`; invalid signatures fail closed.
    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), AlgorithmError>;
}
