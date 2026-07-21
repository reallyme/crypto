// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_ml_kem_512::{
    generate_ml_kem_512_keypair, generate_ml_kem_512_keypair_from_seed, ml_kem_512_decapsulate,
    ml_kem_512_encapsulate, ml_kem_512_encapsulate_derand,
};
use zeroize::Zeroizing;

type TestKeypair = (Vec<u8>, Zeroizing<Vec<u8>>);

trait TestKeypairResult {
    fn into_keypair(self) -> TestKeypair;
}

impl TestKeypairResult for TestKeypair {
    fn into_keypair(self) -> TestKeypair {
        self
    }
}

impl<E: core::fmt::Debug> TestKeypairResult for Result<TestKeypair, E> {
    fn into_keypair(self) -> TestKeypair {
        self.unwrap()
    }
}

#[test]
fn keypair_public_key_size_is_correct() {
    let (pk, sk) = generate_ml_kem_512_keypair().into_keypair();
    assert_eq!(pk.len(), 800);
    assert!(!sk.is_empty());
}

#[test]
fn seeded_keypair_is_deterministic_and_round_trips() {
    let seed = [5u8; 64];
    let (pk1, sk1) = generate_ml_kem_512_keypair_from_seed(&seed).unwrap();
    let (pk2, sk2) = generate_ml_kem_512_keypair_from_seed(&seed).unwrap();

    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    assert_eq!(sk1.as_slice(), seed.as_slice());

    let (ct, ss1) = ml_kem_512_encapsulate(&pk1).unwrap();
    let ss2 = ml_kem_512_decapsulate(&ct, &sk1).unwrap();
    assert_eq!(ss1, ss2);

    let (pk3, _sk3) = generate_ml_kem_512_keypair_from_seed(&[6u8; 64]).unwrap();
    assert_ne!(pk1, pk3);
}

#[test]
fn derandomized_encapsulation_is_deterministic() {
    let (pk, sk) = generate_ml_kem_512_keypair_from_seed(&[7u8; 64]).unwrap();
    let randomness = [9u8; 32];

    let (ct1, ss1) = ml_kem_512_encapsulate_derand(&pk, &randomness).unwrap();
    let (ct2, ss2) = ml_kem_512_encapsulate_derand(&pk, &randomness).unwrap();

    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
    assert_eq!(ml_kem_512_decapsulate(&ct1, &sk).unwrap(), ss1);

    let (ct3, _ss3) = ml_kem_512_encapsulate_derand(&pk, &[10u8; 32]).unwrap();
    assert_ne!(ct1, ct3);
}

#[test]
fn derandomized_encapsulation_rejects_bad_lengths() {
    let (pk, _sk) = generate_ml_kem_512_keypair_from_seed(&[8u8; 64]).unwrap();
    assert!(ml_kem_512_encapsulate_derand(&pk, &[0u8; 31]).is_err());
    assert!(ml_kem_512_encapsulate_derand(&pk[..799], &[0u8; 32]).is_err());
}

#[test]
fn encapsulate_decapsulate_roundtrip() {
    let (pk, sk) = generate_ml_kem_512_keypair().into_keypair();

    let (ct, ss1) = ml_kem_512_encapsulate(&pk).unwrap();
    assert_eq!(ct.len(), 768);
    assert_eq!(ss1.len(), 32);

    let ss2 = ml_kem_512_decapsulate(&ct, &sk).unwrap();
    assert_eq!(ss1, ss2);
}

#[test]
fn invalid_ciphertext_length_fails() {
    let (_pk, sk) = generate_ml_kem_512_keypair().into_keypair();
    for len in [0usize, 1, 10, 767, 769] {
        let bad_ct = vec![0u8; len];
        assert!(ml_kem_512_decapsulate(&bad_ct, &sk).is_err());
    }
}

#[test]
fn modified_ciphertext_changes_secret() {
    let (pk, sk) = generate_ml_kem_512_keypair().into_keypair();

    let (ct, ss1) = ml_kem_512_encapsulate(&pk).unwrap();
    let mut ct2 = ct.clone();
    ct2[0] ^= 0x01;

    let ss2 = ml_kem_512_decapsulate(&ct2, &sk).unwrap();
    assert_ne!(ss1, ss2);
}

#[test]
fn wrong_secret_key_does_not_recover_secret() {
    let (pk, _sk1) = generate_ml_kem_512_keypair().into_keypair();
    let (_pk2, sk2) = generate_ml_kem_512_keypair().into_keypair();

    let (ct, ss1) = ml_kem_512_encapsulate(&pk).unwrap();
    let ss2 = ml_kem_512_decapsulate(&ct, &sk2).unwrap();

    assert_ne!(ss1, ss2);
}

#[test]
fn keypairs_are_unique() {
    let (pk1, sk1) = generate_ml_kem_512_keypair().into_keypair();
    let (pk2, sk2) = generate_ml_kem_512_keypair().into_keypair();

    assert_ne!(pk1, pk2);
    assert_ne!(sk1, sk2);
}

#[test]
fn invalid_public_key_length_fails() {
    for len in [0usize, 1, 10, 799, 801] {
        let bad = vec![0u8; len];
        assert!(ml_kem_512_encapsulate(&bad).is_err());
    }
}

#[test]
fn invalid_secret_key_length_fails() {
    let (_pk, sk) = generate_ml_kem_512_keypair().into_keypair();
    let expected = sk.len();
    for len in [0usize, 1, 10, expected.saturating_sub(1)] {
        let bad_sk = vec![0u8; len];
        let ct = vec![0u8; 768];
        assert!(ml_kem_512_decapsulate(&ct, &bad_sk).is_err());
    }
}
