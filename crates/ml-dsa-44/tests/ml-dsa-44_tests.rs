// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use crypto_ml_dsa_44::{
    generate_ml_dsa_44_keypair, generate_ml_dsa_44_keypair_from_seed, sign_ml_dsa_44,
    verify_ml_dsa_44,
};
use zeroize::Zeroizing;

// FIPS 204 (ML-DSA-44) fixed sizes
const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1312;
const ML_DSA_44_SECRET_SEED_LEN: usize = 32;
const ML_DSA_44_SIGNATURE_LEN: usize = 2420;

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
    let (pk, sk) = generate_ml_dsa_44_keypair().into_keypair();
    assert_eq!(
        pk.len(),
        ML_DSA_44_PUBLIC_KEY_LEN,
        "ML-DSA-44 public key size"
    );
    assert_eq!(
        sk.len(),
        ML_DSA_44_SECRET_SEED_LEN,
        "ML-DSA-44 secret seed size"
    );
}

#[test]
fn seeded_keypair_is_deterministic_and_signs() {
    let seed = [7u8; ML_DSA_44_SECRET_SEED_LEN];
    let (pk1, sk1) = generate_ml_dsa_44_keypair_from_seed(&seed).into_keypair();
    let (pk2, sk2) = generate_ml_dsa_44_keypair_from_seed(&seed).into_keypair();

    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    assert_eq!(sk1.as_slice(), seed.as_slice());

    let sig = sign_ml_dsa_44(&sk1, b"seeded ml-dsa-44").unwrap();
    verify_ml_dsa_44(&pk1, b"seeded ml-dsa-44", &sig).unwrap();

    let (pk3, _sk3) = generate_ml_dsa_44_keypair_from_seed(&[8u8; 32]).into_keypair();
    assert_ne!(pk1, pk3);
}

#[test]
fn per_primitive_header_documents_seed_secret_shape() {
    let header = include_str!("../abi/ml_dsa_44_abi.h");

    assert!(header.contains("#define ML_DSA_44_SECRET_SEED_LEN   32"));
    assert!(!header.contains("2560"));
    assert!(!header.contains("ML_DSA_44_SECRET_KEY_LEN"));
}

#[test]
fn signature_size_is_correct() {
    let (_pk, sk) = generate_ml_dsa_44_keypair().into_keypair();
    let msg = b"ml-dsa-44 test message";

    let sig = sign_ml_dsa_44(&sk, msg).unwrap();
    assert_eq!(
        sig.len(),
        ML_DSA_44_SIGNATURE_LEN,
        "ML-DSA-44 signature size"
    );
}

#[test]
fn sign_and_verify_roundtrip() {
    let (pk, sk) = generate_ml_dsa_44_keypair().into_keypair();
    let msg = b"ml-dsa-44 test";

    let sig = sign_ml_dsa_44(&sk, msg).unwrap();
    verify_ml_dsa_44(&pk, msg, &sig).unwrap();
}

#[test]
fn verification_fails_on_modified_message() {
    let (pk, sk) = generate_ml_dsa_44_keypair().into_keypair();
    let msg = b"original message";
    let sig = sign_ml_dsa_44(&sk, msg).unwrap();

    let tampered = b"original messagf";
    assert!(matches!(
        verify_ml_dsa_44(&pk, tampered, &sig),
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    ));
}

#[test]
fn verification_fails_on_modified_signature() {
    let (pk, sk) = generate_ml_dsa_44_keypair().into_keypair();
    let msg = b"test message";

    let mut sig = sign_ml_dsa_44(&sk, msg).unwrap();
    sig[0] ^= 0x01;

    assert!(matches!(
        verify_ml_dsa_44(&pk, msg, &sig),
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    ));
}

#[test]
fn signature_does_not_verify_under_different_key() {
    let (_pk1, sk1) = generate_ml_dsa_44_keypair().into_keypair();
    let (pk2, _sk2) = generate_ml_dsa_44_keypair().into_keypair();

    let msg = b"test message";
    let sig = sign_ml_dsa_44(&sk1, msg).unwrap();

    assert!(matches!(
        verify_ml_dsa_44(&pk2, msg, &sig),
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    ));
}

#[test]
fn malformed_lengths_are_rejected() {
    let bad_sk = vec![0u8; ML_DSA_44_SECRET_SEED_LEN - 1];
    let bad_pk = vec![0u8; ML_DSA_44_PUBLIC_KEY_LEN - 1];
    let bad_sig = vec![0u8; ML_DSA_44_SIGNATURE_LEN - 1];

    assert!(matches!(
        sign_ml_dsa_44(&bad_sk, b"msg"),
        Err(CryptoError::InvalidKey)
    ));
    assert!(matches!(
        verify_ml_dsa_44(&bad_pk, b"msg", &bad_sig),
        Err(CryptoError::InvalidKey)
    ));
}
