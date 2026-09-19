// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use zeroize::Zeroizing;

use crate::{P256_SECRET_KEY_LEN, P256_SHA256_DIGEST_LEN};

/// Sign an already-computed SHA-256 digest with deterministic P-256 ECDSA.
///
/// This boundary exists for keystores and protocol engines that own hashing.
/// It signs the supplied 32-byte digest directly through the backend prehash
/// primitive; it never hashes the digest again. The DER output uses the
/// deterministic RFC 6979 signature normalized to low-S form.
pub fn sign_p256_digest_der(secret_key: &[u8], digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret_key = copy_secret_key(secret_key)?;
    let digest = copy_digest(digest)?;
    let signing_key = SigningKey::from_slice(secret_key.as_slice())
        .map_err(|_| signature_error(SignatureFailureKind::InvalidPrivateKey))?;
    let signature: Signature = signing_key
        .sign_prehash(digest.as_slice())
        .map_err(|_| signature_error(SignatureFailureKind::BackendFailure))?;

    // Canonical low-S output prevents the keystore boundary from returning
    // the second, malleated ECDSA representation of the same signature.
    let signature = signature.normalize_s();
    Ok(signature.to_der().as_bytes().to_vec())
}

fn copy_secret_key(secret_key: &[u8]) -> Result<Zeroizing<[u8; P256_SECRET_KEY_LEN]>, CryptoError> {
    let scalar = <[u8; P256_SECRET_KEY_LEN]>::try_from(secret_key)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidPrivateKey))?;
    Ok(Zeroizing::new(scalar))
}

fn copy_digest(digest: &[u8]) -> Result<Zeroizing<[u8; P256_SHA256_DIGEST_LEN]>, CryptoError> {
    let digest = <[u8; P256_SHA256_DIGEST_LEN]>::try_from(digest)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidMessage))?;
    Ok(Zeroizing::new(digest))
}

fn signature_error(kind: SignatureFailureKind) -> CryptoError {
    CryptoError::Signature {
        backend: signature_backend(),
        operation: SignatureOperation::Sign,
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
