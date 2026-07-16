// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// sign.rs

use crypto_core::CryptoError;
use ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// Signs message bytes using secp256k1 ECDSA.
///
/// The public API accepts the original message, hashes it exactly once with
/// SHA-256, and signs that digest with deterministic RFC 6979 ECDSA. Use the
/// prehash trait here deliberately: k256's high-level `Signer` hashes its input
/// as a message, which would otherwise turn this into SHA-256(SHA-256(message)).
/// The returned signature is compact 64-byte `r || s` and normalized to low-S.
pub fn sign_secp256k1(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let sk = SigningKey::from_slice(secret_key).map_err(|_| CryptoError::InvalidKey)?;

    // Prehash
    let digest = Sha256::digest(message);

    // Sign the digest bytes directly; do not route through high-level `Signer`.
    let sig: Signature = sk
        .sign_prehash(digest.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;

    // Enforce low-S normalization
    let sig = sig.normalize_s();

    Ok(sig.to_bytes().to_vec())
}
