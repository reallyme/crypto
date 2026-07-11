// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{Signer, SignerError, SignerFailureKind};

/// Local private-key signer implemented through `crypto_dispatch::sign`.
///
/// This adapter is useful for tests and native development. Production custody
/// should prefer a platform keystore, HSM, QSCD, or remote signing adapter.
#[derive(Debug)]
pub struct DispatchSigner {
    alg: Algorithm,
    private_key: SecretBox<Zeroizing<Vec<u8>>>,
}

impl DispatchSigner {
    /// Create a dispatch-backed signer from owned private-key material.
    ///
    /// Accepts either `Vec<u8>` or `Zeroizing<Vec<u8>>`; the key is stored in
    /// a zeroizing secret wrapper either way.
    pub fn new(alg: Algorithm, private_key: impl Into<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            alg,
            private_key: SecretBox::new(Box::new(private_key.into())),
        }
    }
}

impl Signer for DispatchSigner {
    fn alg(&self) -> Algorithm {
        self.alg
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        crypto_dispatch::sign(
            self.alg,
            self.private_key.expose_secret().as_slice(),
            message,
        )
        .map_err(|source| SignerError::SignFailed {
            algorithm: self.alg,
            kind: SignerFailureKind::DispatchRejected,
            source,
        })
    }
}
