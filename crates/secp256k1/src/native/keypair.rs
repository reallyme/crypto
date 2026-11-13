// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::Generate;
use k256::SecretKey;
use zeroize::{Zeroize, Zeroizing};

/// Generate a secp256k1 keypair with typed entropy failures.
///
/// The public key retains its 33-byte compressed SEC1 representation, and the
/// returned private scalar remains in its existing zeroizing owner. In 0.4 this
/// compatibility name returns `Result`, so an unavailable entropy provider
/// cannot reach the historical infallible provider path.
///
/// # Errors
///
/// Returns [`CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE`] when OS entropy
/// cannot be obtained. Other existing native validation failures propagate.
#[deprecated(note = "use try_generate_secp256k1_keypair")]
pub fn generate_secp256k1_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    try_generate_secp256k1_keypair()
}

/// Generate a secp256k1 keypair with explicit entropy failure handling.
///
/// This is the preferred entry point. The compatibility name delegates here
/// with the same typed error and successful-generation semantics.
pub fn try_generate_secp256k1_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let secret = SecretKey::try_generate()
        .map_err(|_| crypto_core::CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)?;
    let secret_bytes = Zeroizing::new(secret.to_bytes());
    generate_secp256k1_keypair_from_secret_key(secret_bytes.as_ref())
}

/// Derive a secp256k1 keypair from an existing 32-byte secret scalar.
///
/// This is intentionally named `from_secret_key`, not `from_seed`: the input
/// is already the private scalar material and must be a valid secp256k1 secret.
pub fn generate_secp256k1_keypair_from_secret_key(
    secret_key: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let secret =
        SecretKey::from_slice(secret_key).map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
    let signing_key = SigningKey::from(&secret);
    let verifying_key = signing_key.verifying_key();

    let mut secret_stack = secret.to_bytes();
    let secret_bytes = Zeroizing::new(secret_stack.to_vec());
    secret_stack.zeroize();
    let public_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec();

    Ok((public_bytes, secret_bytes))
}
