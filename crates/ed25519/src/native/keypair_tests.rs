// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::generate_ed25519_keypair_with_rng;
use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
use crypto_csprng::SecureRandom;

struct UnavailableEntropy;

impl SecureRandom for UnavailableEntropy {
    fn fill_secure(&mut self, _output: &mut [u8], kind: RngOutputKind) -> Result<(), CryptoError> {
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
