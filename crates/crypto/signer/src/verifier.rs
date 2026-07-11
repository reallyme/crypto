// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::Algorithm;

use crate::VerifierError;

/// Verifier trait for byte strings, mirroring [`Signer`](crate::Signer).
///
/// Verification fails closed: an invalid signature is an error, never a
/// boolean, so a forgotten result check cannot be mistaken for success.
pub trait Verifier {
    /// Return the cryptographic algorithm used by this verifier.
    fn alg(&self) -> Algorithm;

    /// Verify `signature` over `message`. Returns `Ok(())` only if the
    /// signature is valid for this verifier's public key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifierError>;
}
