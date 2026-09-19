// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;
use zeroize::Zeroizing;

use crate::P256_SHA256_DIGEST_LEN;

/// Verify a canonical low-S DER P-256 ECDSA signature over a SHA-256 digest.
///
/// The digest must be exactly 32 bytes and is passed directly to the backend
/// prehash verifier. This canonical keystore-oriented boundary rejects high-S
/// twins; [`super::verify_p256_der_prehash`] retains its documented behavior of
/// accepting interoperable high-S ES256 signatures over message bytes.
pub fn verify_p256_digest_der(
    signature_der: &[u8],
    digest: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    let digest = copy_digest(digest)?;
    let public_key = PublicKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidPublicKey))?;
    let verifying_key = VerifyingKey::from(public_key);
    let signature = Signature::from_der(signature_der)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidSignature))?;

    if signature.normalize_s() != signature {
        return Err(signature_error(SignatureFailureKind::InvalidSignature));
    }

    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidSignature))
}

fn copy_digest(digest: &[u8]) -> Result<Zeroizing<[u8; P256_SHA256_DIGEST_LEN]>, CryptoError> {
    let digest = <[u8; P256_SHA256_DIGEST_LEN]>::try_from(digest)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidMessage))?;
    Ok(Zeroizing::new(digest))
}

fn signature_error(kind: SignatureFailureKind) -> CryptoError {
    CryptoError::Signature {
        backend: signature_backend(),
        operation: SignatureOperation::Verify,
        kind,
    }
}

fn signature_backend() -> SignatureBackend {
    #[cfg(target_arch = "wasm32")]
    {
        SignatureBackend::Wasm
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SignatureBackend::Native
    }
}
