// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
use crypto_core::{CryptoError, RngFailureKind, RngOutputKind};
use crypto_csprng::{
    generate_aead_nonce_12, generate_aes256_gcm_key, generate_argon2_salt_16,
    generate_argon2_salt_32, generate_bytes, generate_ml_dsa_87_seed, generate_ml_kem_1024_seed,
    Aes256GcmKeyMaterial, MlDsa87Seed, MlKem1024Seed, SecureRandom, AES_256_GCM_KEY_LENGTH,
    ML_DSA_87_SEED_LENGTH, ML_KEM_1024_SEED_LENGTH,
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
    assert_eq!(format!("{salt16:?}"), "Argon2Salt16(<redacted>)");
    assert_eq!(format!("{salt32:?}"), "Argon2Salt32(<redacted>)");
}

#[test]
fn salt_equality_preserves_value_semantics() {
    let mut first_rng = DeterministicRng::new(9);
    let mut second_rng = DeterministicRng::new(9);
    let mut different_rng = DeterministicRng::new(10);

    let first16 = generate_argon2_salt_16(&mut first_rng);
    let second16 = generate_argon2_salt_16(&mut second_rng);
    let different16 = generate_argon2_salt_16(&mut different_rng);
    let first32 = generate_argon2_salt_32(&mut first_rng);
    let second32 = generate_argon2_salt_32(&mut second_rng);
    let different32 = generate_argon2_salt_32(&mut different_rng);

    assert!(first16.is_ok());
    assert!(second16.is_ok());
    assert!(different16.is_ok());
    assert_eq!(first16, second16);
    assert_ne!(first16, different16);
    assert!(first32.is_ok());
    assert!(second32.is_ok());
    assert!(different32.is_ok());
    assert_eq!(first32, second32);
    assert_ne!(first32, different32);
}

#[test]
fn ssp_generation_uses_fixed_size_secret_owners() {
    let mut rng = DeterministicRng::new(3);

    let aes_key = generate_aes256_gcm_key(&mut rng);
    let ml_kem_seed = generate_ml_kem_1024_seed(&mut rng);
    let ml_dsa_seed = generate_ml_dsa_87_seed(&mut rng);

    assert!(aes_key.is_ok());
    assert!(ml_kem_seed.is_ok());
    assert!(ml_dsa_seed.is_ok());

    let aes_key: Aes256GcmKeyMaterial = match aes_key {
        Ok(value) => value,
        Err(_) => return,
    };
    let ml_kem_seed: MlKem1024Seed = match ml_kem_seed {
        Ok(value) => value,
        Err(_) => return,
    };
    let ml_dsa_seed: MlDsa87Seed = match ml_dsa_seed {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(aes_key.as_bytes().len(), AES_256_GCM_KEY_LENGTH);
    assert_eq!(aes_key.as_bytes()[0], 3);
    assert_eq!(aes_key.as_bytes()[AES_256_GCM_KEY_LENGTH - 1], 34);
    assert_eq!(ml_kem_seed.as_bytes().len(), ML_KEM_1024_SEED_LENGTH);
    assert_eq!(ml_kem_seed.as_bytes()[0], 35);
    assert_eq!(ml_kem_seed.as_bytes()[ML_KEM_1024_SEED_LENGTH - 1], 98);
    assert_eq!(ml_dsa_seed.as_bytes().len(), ML_DSA_87_SEED_LENGTH);
    assert_eq!(ml_dsa_seed.as_bytes()[0], 99);
    assert_eq!(ml_dsa_seed.as_bytes()[ML_DSA_87_SEED_LENGTH - 1], 130);
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

#[test]
fn ssp_entropy_failures_preserve_output_kind() {
    let mut rng = FailingRng;

    assert!(matches!(
        generate_aes256_gcm_key(&mut rng),
        Err(CryptoError::Rng {
            output: RngOutputKind::Aes256GcmKey,
            kind: RngFailureKind::EntropyUnavailable,
        })
    ));
    assert!(matches!(
        generate_ml_kem_1024_seed(&mut rng),
        Err(CryptoError::Rng {
            output: RngOutputKind::MlKem1024Seed,
            kind: RngFailureKind::EntropyUnavailable,
        })
    ));
    assert!(matches!(
        generate_ml_dsa_87_seed(&mut rng),
        Err(CryptoError::Rng {
            output: RngOutputKind::MlDsa87Seed,
            kind: RngFailureKind::EntropyUnavailable,
        })
    ));
}
