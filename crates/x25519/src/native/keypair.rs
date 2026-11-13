// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::CryptoError;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Generate an X25519 keypair with typed entropy failures.
///
/// The public key retains its 32-byte representation, and the
/// returned private scalar remains in its existing zeroizing owner. In 0.4 this
/// compatibility name returns `Result`, so an unavailable entropy provider
/// cannot reach the historical infallible provider path.
///
/// # Errors
///
/// Returns [`CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE`] when OS entropy
/// cannot be obtained. Other existing native validation failures propagate.
#[deprecated(note = "use try_generate_x25519_keypair")]
pub fn generate_x25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    try_generate_x25519_keypair()
}

/// Generate an X25519 keypair with explicit entropy failure handling.
///
/// The seed remains zeroizing even if the OS reports a partial-fill failure.
pub fn try_generate_x25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut_slice())
        .map_err(|_| crypto_core::CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)?;
    Ok(generate_x25519_keypair_from_seed(&seed))
}

/// Generate an X25519 keypair deterministically from a 32-byte seed.
///
/// The seed is used directly as the secret scalar (X25519 clamps at use time),
/// so this is the derandomized counterpart to [`generate_x25519_keypair`]: it
/// lets a caller supply its own CSPRNG output for cases that must stay
/// reproducible — deterministic test vectors, or a caller-controlled entropy
/// source. The same 32 seed bytes always yield the same keypair.
///
/// Returns:
/// - public key: 32 bytes
/// - secret key: the 32 seed bytes, in a zeroizing wrapper
pub fn generate_x25519_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let secret = StaticSecret::from(*seed);
    let public = PublicKey::from(&secret);

    let secret_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(secret.to_bytes());

    (
        public.as_bytes().to_vec(),
        Zeroizing::new(secret_bytes.to_vec()),
    )
}
