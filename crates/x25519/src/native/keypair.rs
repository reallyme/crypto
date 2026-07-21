// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Generate an X25519 keypair.
///
/// Returns:
/// - public key: 32 bytes
/// - secret key: 32 bytes, in a zeroizing wrapper so it is wiped when the
///   caller drops it
pub fn generate_x25519_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    // Keep the stack copy of the secret scalar inside a zeroizing wrapper.
    let secret_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(secret.to_bytes());

    (
        public.as_bytes().to_vec(),
        Zeroizing::new(secret_bytes.to_vec()),
    )
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
