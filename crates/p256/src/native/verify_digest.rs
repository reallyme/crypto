// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::P256Sha256Digest;
use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;

/// Verify a canonical low-S DER P-256 ECDSA signature over a SHA-256 digest.
///
/// The typed digest is passed directly to the backend prehash verifier. This
/// canonical keystore-oriented boundary rejects high-S twins;
/// [`super::verify_p256_sha256_message_der_interoperable`] accepts high-S ES256
/// signatures over original message bytes for ecosystem interoperability.
pub fn verify_p256_sha256_digest_low_s_der(
    signature_der: &[u8],
    digest: &P256Sha256Digest,
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    let public_key = PublicKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidPublicKey))?;
    let verifying_key = VerifyingKey::from(public_key);
    let signature = Signature::from_der(signature_der)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidSignature))?;

    if signature.normalize_s() != signature {
        return Err(signature_error(SignatureFailureKind::InvalidSignature));
    }

    verifying_key
        .verify_prehash(digest.as_bytes(), &signature)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidSignature))
}

/// Compatibility boundary for verifying against an untyped digest byte slice.
#[deprecated(
    since = "0.3.16",
    note = "construct P256Sha256Digest and use verify_p256_sha256_digest_low_s_der"
)]
pub fn verify_p256_digest_der(
    signature_der: &[u8],
    digest: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    let digest = P256Sha256Digest::try_from_slice(digest)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidMessage))?;
    verify_p256_sha256_digest_low_s_der(signature_der, &digest, public_key_sec1)
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
