// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 root facade routed through the signature operation layer.

use crypto_core::{Algorithm, CryptoError};
use zeroize::Zeroizing;

// The primitive only defines these encoding helpers when a backend is present.
#[cfg(any(feature = "native", feature = "wasm"))]
pub use crypto_ed25519::{assert_public_key, decode_public_key, encode_public_key};

/// Generate a standard Ed25519 keypair through the signature operation owner.
pub fn generate_ed25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::generate_key_pair(Algorithm::Ed25519)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
}

/// Reconstruct an Ed25519 keypair from a 32-byte seed through the operation owner.
pub fn generate_ed25519_keypair_from_seed(
    seed: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    crate::operations::signature::derive_key_pair(Algorithm::Ed25519, seed)
        .map(|key_pair| (key_pair.public_key, key_pair.secret_key))
}

/// Sign a message using a 32-byte Ed25519 seed.
pub fn sign_ed25519(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::operations::signature::sign(Algorithm::Ed25519, secret_key, message)
}

/// Verify a detached Ed25519 signature.
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    crate::operations::signature::verify(Algorithm::Ed25519, public_key, message, signature)
}
