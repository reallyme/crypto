// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;
use crypto_dispatch::AlgorithmError;

use crate::{Verifier, VerifierError, VerifierFailureKind};

/// Public-key verifier implemented through `crypto_dispatch::verify`.
///
/// Public keys are not secret, but the wrapper still keeps the bytes
/// private to prevent accidental mutation between construction and use.
#[derive(Debug)]
pub struct DispatchVerifier {
    alg: Algorithm,
    public_key: Vec<u8>,
}

impl DispatchVerifier {
    /// Create a dispatch-backed verifier from a public key.
    pub fn new(alg: Algorithm, public_key: Vec<u8>) -> Self {
        Self { alg, public_key }
    }

    /// The public key this verifier checks against.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl Verifier for DispatchVerifier {
    fn alg(&self) -> Algorithm {
        self.alg
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifierError> {
        crypto_dispatch::verify(self.alg, &self.public_key, message, signature).map_err(|source| {
            let kind = match &source {
                AlgorithmError::SignatureInvalid(_) => VerifierFailureKind::SignatureInvalid,
                _ => VerifierFailureKind::DispatchRejected,
            };
            VerifierError::VerifyFailed {
                algorithm: self.alg,
                kind,
                source,
            }
        })
    }
}
