// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_core::{CryptoError, RngOutputKind};
use crypto_csprng::{generate_bytes, OsSecureRandom, SecureRandom};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

const ED25519_SEED_LENGTH: usize = 32;

/// Generate a standard Ed25519 keypair.
///
/// Returns `(public_key, private_seed)`, each 32 bytes.
///
/// The private seed is returned in a zeroizing wrapper so it is wiped
/// when the caller drops it.
pub fn generate_ed25519_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    generate_ed25519_keypair_with_rng(&mut OsSecureRandom)
}

fn generate_ed25519_keypair_with_rng(
    rng: &mut impl SecureRandom,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError> {
    // Draw the seed through the workspace OS-CSPRNG boundary so entropy
    // failures remain typed instead of panicking inside a userspace RNG.
    let seed = generate_bytes::<ED25519_SEED_LENGTH>(rng, RngOutputKind::Ed25519Seed)?;
    let signing = SigningKey::from_bytes(seed.as_bytes());

    // Keep the stack copy of the seed inside a zeroizing wrapper as well.
    let private_seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing.to_bytes());
    let public_key: [u8; 32] = signing.verifying_key().to_bytes();

    Ok((public_key.to_vec(), Zeroizing::new(private_seed.to_vec())))
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

#[cfg(test)]
mod tests {
    use super::generate_ed25519_keypair_with_rng;
    use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
    use crypto_csprng::SecureRandom;

    struct UnavailableEntropy;

    impl SecureRandom for UnavailableEntropy {
        fn fill_secure(
            &mut self,
            _output: &mut [u8],
            kind: RngOutputKind,
        ) -> Result<(), CryptoError> {
            Err(CryptoError::Rng {
                output: kind,
                kind: RngFailureKind::EntropyUnavailable,
            })
        }
    }

    #[test]
    fn keygen_propagates_typed_entropy_failure() {
        let result = generate_ed25519_keypair_with_rng(&mut UnavailableEntropy);
        assert!(matches!(
            result,
            Err(CryptoError::Rng {
                output: RngOutputKind::Ed25519Seed,
                kind: RngFailureKind::EntropyUnavailable,
            })
        ));
    }
}
