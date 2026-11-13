// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::generate_ed25519_keypair_with_rng;
use crypto_core::{CryptoError, RngOutputKind};
use crypto_csprng::SecureRandom;

struct UnavailableEntropy;

impl SecureRandom for UnavailableEntropy {
    fn fill_secure(&mut self, _output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}

#[test]
fn keygen_propagates_typed_entropy_failure() {
    let result = generate_ed25519_keypair_with_rng(&mut UnavailableEntropy);
    assert!(matches!(
        result,
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    ));
}
