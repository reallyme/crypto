// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;

use crate::SignerError;

/// Signer trait for byte strings.
pub trait Signer {
    /// Return the cryptographic algorithm used by this signer.
    fn alg(&self) -> Algorithm;

    /// Sign `message` and return signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}
