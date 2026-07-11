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
#![cfg(feature = "native")]

use crypto_ml_dsa_87::{
    generate_ml_dsa_87_keypair, generate_ml_dsa_87_keypair_from_seed, sign_ml_dsa_87,
    verify_ml_dsa_87,
};
use zeroize::Zeroizing;

// FIPS 204 (ML-DSA-87) fixed sizes
const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
const ML_DSA_87_SECRET_SEED_LEN: usize = 32;
const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

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
fn key_sizes_are_correct() {
    let (pk, sk) = generate_ml_dsa_87_keypair().into_keypair();
    assert_eq!(
        pk.len(),
        ML_DSA_87_PUBLIC_KEY_LEN,
        "ML-DSA-87 public key size"
    );
    assert_eq!(
        sk.len(),
        ML_DSA_87_SECRET_SEED_LEN,
        "ML-DSA-87 secret seed size"
    );
}

#[test]
fn seeded_keypair_is_deterministic_and_signs() {
    let seed = [7u8; ML_DSA_87_SECRET_SEED_LEN];
    let (pk1, sk1) = generate_ml_dsa_87_keypair_from_seed(&seed).into_keypair();
    let (pk2, sk2) = generate_ml_dsa_87_keypair_from_seed(&seed).into_keypair();

    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    assert_eq!(sk1.as_slice(), seed.as_slice());

    let sig = sign_ml_dsa_87(&sk1, b"seeded ml-dsa-87").unwrap();
    verify_ml_dsa_87(&pk1, b"seeded ml-dsa-87", &sig).unwrap();

    let (pk3, _sk3) = generate_ml_dsa_87_keypair_from_seed(&[8u8; 32]).into_keypair();
    assert_ne!(pk1, pk3);
}

#[test]
fn per_primitive_header_documents_seed_secret_shape() {
    let header = include_str!("../abi/ml_dsa_87_abi.h");

    assert!(header.contains("#define ML_DSA_87_SECRET_SEED_LEN   32"));
    assert!(!header.contains("4896"));
    assert!(!header.contains("ML_DSA_87_SECRET_KEY_LEN"));
}

#[test]
fn signature_size_is_correct() {
    let (_pk, sk) = generate_ml_dsa_87_keypair().into_keypair();
    let msg = b"ml-dsa-87 test message";

    let sig = sign_ml_dsa_87(&sk, msg).unwrap();
    assert_eq!(
        sig.len(),
        ML_DSA_87_SIGNATURE_LEN,
        "ML-DSA-87 signature size"
    );
}

#[test]
fn sign_and_verify_roundtrip() {
    let (pk, sk) = generate_ml_dsa_87_keypair().into_keypair();
    let msg = b"ml-dsa-87 test";

    let sig = sign_ml_dsa_87(&sk, msg).unwrap();
    verify_ml_dsa_87(&pk, msg, &sig).unwrap();
}

#[test]
fn verification_fails_on_modified_message() {
    let (pk, sk) = generate_ml_dsa_87_keypair().into_keypair();
    let msg = b"original message";
    let sig = sign_ml_dsa_87(&sk, msg).unwrap();

    let tampered = b"original messagf";
    assert!(verify_ml_dsa_87(&pk, tampered, &sig).is_err());
}

#[test]
fn verification_fails_on_modified_signature() {
    let (pk, sk) = generate_ml_dsa_87_keypair().into_keypair();
    let msg = b"test message";

    let mut sig = sign_ml_dsa_87(&sk, msg).unwrap();
    sig[0] ^= 0x01;

    assert!(verify_ml_dsa_87(&pk, msg, &sig).is_err());
}

#[test]
fn signature_does_not_verify_under_different_key() {
    let (_pk1, sk1) = generate_ml_dsa_87_keypair().into_keypair();
    let (pk2, _sk2) = generate_ml_dsa_87_keypair().into_keypair();

    let msg = b"test message";
    let sig = sign_ml_dsa_87(&sk1, msg).unwrap();

    assert!(verify_ml_dsa_87(&pk2, msg, &sig).is_err());
}

#[test]
fn malformed_lengths_are_rejected() {
    let bad_sk = vec![0u8; ML_DSA_87_SECRET_SEED_LEN - 1];
    let bad_pk = vec![0u8; ML_DSA_87_PUBLIC_KEY_LEN - 1];
    let bad_sig = vec![0u8; ML_DSA_87_SIGNATURE_LEN - 1];

    assert!(sign_ml_dsa_87(&bad_sk, b"msg").is_err());
    assert!(verify_ml_dsa_87(&bad_pk, b"msg", &bad_sig).is_err());
}
