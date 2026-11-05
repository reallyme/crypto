// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// sign.rs

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::{sign_p256_sha256_digest_low_s_der, P256Sha256Digest};

/// Hash `message` once with SHA-256 and produce deterministic low-S DER.
///
/// This is the preferred message-signing boundary. The input is always the
/// original message, never a caller-computed digest. Canonical low-S output
/// prevents the signer from producing the second ECDSA representation of the
/// same signature.
pub fn sign_p256_sha256_message_low_s_der(
    secret_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let digest = P256Sha256Digest::new(Sha256::digest(message).into());
    sign_p256_sha256_digest_low_s_der(secret_key, &digest)
}

/// Sign with P-256 ECDSA.
///
/// - SHA-256 prehash
/// - DER-encoded signature
///
/// This message-signing API preserves the ECDSA signature produced by the
/// backend, including a possible high-S value. Callers requiring canonical
/// low-S signatures should use [`crate::sign_p256_sha256_message_low_s_der`].
#[deprecated(
    since = "0.3.16",
    note = "use sign_p256_sha256_message_low_s_der; this legacy name accepts message bytes and preserves backend S"
)]
pub fn sign_p256_der_prehash(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let sk = SigningKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;

    let digest = Sha256::digest(message);
    let sig: Signature = sk
        .sign_prehash(&digest)
        .map_err(|_| legacy_signature_error(SignatureFailureKind::BackendFailure))?;

    Ok(sig.to_der().as_bytes().to_vec())
}

fn legacy_signature_error(kind: SignatureFailureKind) -> CryptoError {
    CryptoError::Signature {
        backend: SignatureBackend::Native,
        operation: SignatureOperation::Sign,
        kind,
    }
}
