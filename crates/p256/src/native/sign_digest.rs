// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use zeroize::Zeroizing;

use crate::{P256Sha256Digest, P256_SECRET_KEY_LEN};

/// Sign a typed SHA-256 digest with deterministic low-S P-256 ECDSA DER.
///
/// This boundary exists for keystores and protocol engines that own hashing.
/// It signs the digest directly through the backend prehash primitive and
/// never hashes it again. The digest type prevents accidental message input.
pub fn sign_p256_sha256_digest_low_s_der(
    secret_key: &[u8],
    digest: &P256Sha256Digest,
) -> Result<Vec<u8>, CryptoError> {
    let secret_key = copy_secret_key(secret_key)?;
    let signing_key = SigningKey::from_slice(secret_key.as_slice())
        .map_err(|_| signature_error(SignatureFailureKind::InvalidPrivateKey))?;
    let signature: Signature = signing_key
        .sign_prehash(digest.as_bytes())
        .map_err(|_| signature_error(SignatureFailureKind::BackendFailure))?;

    // Canonical low-S output prevents the keystore boundary from returning
    // the second, malleated ECDSA representation of the same signature.
    let signature = signature.normalize_s();
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Compatibility boundary for signing an untyped digest byte slice.
#[deprecated(
    since = "0.3.16",
    note = "construct P256Sha256Digest and use sign_p256_sha256_digest_low_s_der"
)]
pub fn sign_p256_digest_der(secret_key: &[u8], digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let digest = P256Sha256Digest::try_from_slice(digest)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidMessage))?;
    sign_p256_sha256_digest_low_s_der(secret_key, &digest)
}

fn copy_secret_key(secret_key: &[u8]) -> Result<Zeroizing<[u8; P256_SECRET_KEY_LEN]>, CryptoError> {
    let scalar = <[u8; P256_SECRET_KEY_LEN]>::try_from(secret_key)
        .map_err(|_| signature_error(SignatureFailureKind::InvalidPrivateKey))?;
    Ok(Zeroizing::new(scalar))
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
