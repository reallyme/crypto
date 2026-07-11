// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
use crypto_csprng::{
    generate_aead_nonce_12, generate_argon2_salt_16, generate_argon2_salt_32, generate_bytes,
    SecureRandom,
};

struct DeterministicRng {
    next: u8,
}

impl DeterministicRng {
    const fn new(start: u8) -> Self {
        Self { next: start }
    }
}

impl SecureRandom for DeterministicRng {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        for byte in output {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }

        Ok(())
    }
}

struct FailingRng;

impl SecureRandom for FailingRng {
    fn fill_secure(&mut self, _output: &mut [u8], kind: RngOutputKind) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output: kind,
            kind: RngFailureKind::EntropyUnavailable,
        })
    }
}

#[test]
fn nonce_generation_produces_12_bytes() {
    let mut rng = DeterministicRng::new(1);
    let nonce_result = generate_aead_nonce_12(&mut rng);
    assert!(nonce_result.is_ok());

    let nonce = match nonce_result {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(nonce.as_bytes().len(), 12);
    assert_eq!(nonce.as_bytes()[0], 1);
    assert_eq!(nonce.as_bytes()[11], 12);
}

#[test]
fn salt_generation_produces_expected_lengths() {
    let mut rng = DeterministicRng::new(9);

    let salt16 = generate_argon2_salt_16(&mut rng);
    let salt32 = generate_argon2_salt_32(&mut rng);

    assert!(salt16.is_ok());
    assert!(salt32.is_ok());

    let salt16 = match salt16 {
        Ok(value) => value,
        Err(_) => return,
    };
    let salt32 = match salt32 {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(salt16.as_bytes().len(), 16);
    assert_eq!(salt32.as_bytes().len(), 32);
}

#[test]
fn generic_output_rejects_zero_length() {
    let mut rng = DeterministicRng::new(0);
    let result = generate_bytes::<0>(&mut rng, RngOutputKind::Generic);

    assert!(matches!(
        result,
        Err(CryptoError::Rng {
            output: RngOutputKind::Generic,
            kind: RngFailureKind::InvalidOutputLength,
        })
    ));
}

#[test]
fn entropy_failure_is_propagated() {
    let mut rng = FailingRng;
    let result = generate_aead_nonce_12(&mut rng);

    assert_eq!(
        result,
        Err(CryptoError::Rng {
            output: RngOutputKind::AeadNonce12,
            kind: RngFailureKind::EntropyUnavailable,
        })
    );
}
