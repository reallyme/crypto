// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::PublicKey;
use sha2::{Digest, Sha384};

/// Verify a DER-encoded P-384 ECDSA signature over `message`.
///
/// P-384 signatures are not canonicalized to low-S here. JOSE, PKI, and
/// government-profile ecosystems generally define validity over ECDSA rather
/// than a unique signature representation, so rejecting high-S signatures
/// would reduce interoperability with otherwise conforming implementations.
pub fn verify_p384_der_prehash(
    signature_der: &[u8],
    message: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    let public_key =
        PublicKey::from_sec1_bytes(public_key_sec1).map_err(|_| CryptoError::InvalidKey)?;
    let verifying_key = VerifyingKey::from(public_key);
    let signature = Signature::from_der(signature_der).map_err(|_| CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Verify,
        kind: SignatureFailureKind::InvalidSignature,
    })?;
    if verifying_key
        .verify_prehash(&Sha384::digest(message), &signature)
        .is_ok()
    {
        Ok(())
    } else {
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    }
}
