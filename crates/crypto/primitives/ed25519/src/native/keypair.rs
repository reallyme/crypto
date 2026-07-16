// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// Generate a standard Ed25519 keypair.
///
/// Returns `(public_key, private_seed)`, each 32 bytes.
///
/// The private seed is returned in a zeroizing wrapper so it is wiped
/// when the caller drops it.
pub fn generate_ed25519_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut rng = rand::rng();
    let signing = SigningKey::generate(&mut rng);

    // Keep the stack copy of the seed inside a zeroizing wrapper as well.
    let private_seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing.to_bytes());
    let public_key: [u8; 32] = signing.verifying_key().to_bytes();

    (public_key.to_vec(), Zeroizing::new(private_seed.to_vec()))
}

/// Generate an Ed25519 keypair deterministically from a 32-byte seed.
///
/// The Ed25519 private key *is* the 32-byte seed (RFC 8032), so this is the
/// derandomized counterpart to [`generate_ed25519_keypair`]: it lets a caller
/// supply its own CSPRNG output for cases that must stay reproducible:
/// deterministic test vectors, or a caller-controlled entropy source. The same
/// 32 seed bytes always yield the same keypair.
///
/// Returns `(public_key, private_seed)`, each 32 bytes; the private seed is the
/// 32 input bytes, in a zeroizing wrapper.
pub fn generate_ed25519_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let signing = SigningKey::from_bytes(seed);

    let private_seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing.to_bytes());
    let public_key: [u8; 32] = signing.verifying_key().to_bytes();

    (public_key.to_vec(), Zeroizing::new(private_seed.to_vec()))
}
