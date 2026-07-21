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

use crypto_core::CryptoError;
use crypto_x25519::{
    derive_x25519_shared_secret, generate_x25519_keypair, generate_x25519_keypair_from_seed,
};
use zeroize::Zeroizing;

type TestKeypair = (Vec<u8>, Zeroizing<Vec<u8>>);

trait IntoTestKeypairResult {
    fn into_test_result(self) -> Result<TestKeypair, CryptoError>;
}

impl IntoTestKeypairResult for TestKeypair {
    fn into_test_result(self) -> Result<TestKeypair, CryptoError> {
        Ok(self)
    }
}

impl IntoTestKeypairResult for Result<TestKeypair, CryptoError> {
    fn into_test_result(self) -> Result<TestKeypair, CryptoError> {
        self
    }
}

#[test]
fn keypair_sizes_are_correct() -> Result<(), CryptoError> {
    let (pk, sk) = generate_x25519_keypair().into_test_result()?;
    assert_eq!(pk.len(), 32);
    assert_eq!(sk.len(), 32);
    Ok(())
}

#[test]
fn shared_secret_matches_both_sides() -> Result<(), CryptoError> {
    let (pk_a, sk_a) = generate_x25519_keypair().into_test_result()?;
    let (pk_b, sk_b) = generate_x25519_keypair().into_test_result()?;

    let ss1 = derive_x25519_shared_secret(&sk_a, &pk_b)?;
    let ss2 = derive_x25519_shared_secret(&sk_b, &pk_a)?;

    assert_eq!(ss1, ss2);
    assert_eq!(ss1.len(), 32);
    Ok(())
}

#[test]
fn invalid_key_size_fails() -> Result<(), CryptoError> {
    let (pk, sk) = generate_x25519_keypair().into_test_result()?;

    for bad_len in [0usize, 1, 10, 31, 33] {
        let bad = vec![0u8; bad_len];
        assert!(derive_x25519_shared_secret(&bad, &pk).is_err());
        assert!(derive_x25519_shared_secret(&sk, &bad).is_err());
    }
    Ok(())
}

#[test]
fn shared_secret_is_not_all_zero() -> Result<(), CryptoError> {
    let (_pk_a, sk_a) = generate_x25519_keypair().into_test_result()?;
    let (pk_b, _sk_b) = generate_x25519_keypair().into_test_result()?;

    let ss = derive_x25519_shared_secret(&sk_a, &pk_b)?;

    assert!(
        ss.iter().any(|&b| b != 0),
        "X25519 shared secret must not be all-zero"
    );
    Ok(())
}

#[test]
fn low_order_public_key_is_rejected() -> Result<(), CryptoError> {
    let (_pk, sk) = generate_x25519_keypair().into_test_result()?;

    // The all-zero point is low-order: it drives the shared secret to zero
    // (a world-known value). Derivation must fail closed rather than return
    // that secret, and must not panic.
    let bogus_pk = [0u8; 32];
    let result = derive_x25519_shared_secret(&sk, &bogus_pk);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn seeded_keypair_is_deterministic_and_correct_sizes() {
    let seed = [7u8; 32];
    let (pk1, sk1) = generate_x25519_keypair_from_seed(&seed);
    let (pk2, sk2) = generate_x25519_keypair_from_seed(&seed);

    // Same seed → same keypair (the whole point of the derandomized variant).
    assert_eq!(pk1, pk2);
    assert_eq!(sk1.as_slice(), sk2.as_slice());
    assert_eq!(pk1.len(), 32);
    assert_eq!(sk1.len(), 32);
    // The secret key is exactly the 32 seed bytes.
    assert_eq!(sk1.as_slice(), &seed);

    // A different seed yields a different public key.
    let (pk3, _sk3) = generate_x25519_keypair_from_seed(&[8u8; 32]);
    assert_ne!(pk1, pk3);
}

#[test]
fn seeded_keypairs_agree_on_shared_secret() -> Result<(), CryptoError> {
    let (pk_a, sk_a) = generate_x25519_keypair_from_seed(&[1u8; 32]);
    let (pk_b, sk_b) = generate_x25519_keypair_from_seed(&[2u8; 32]);

    let ss1 = derive_x25519_shared_secret(&sk_a, &pk_b)?;
    let ss2 = derive_x25519_shared_secret(&sk_b, &pk_a)?;
    assert_eq!(ss1, ss2);
    Ok(())
}

#[test]
fn rfc7748_vector_matches() {
    let alice_secret =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .expect("alice secret must decode");
    let bob_secret =
        hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .expect("bob secret must decode");
    let alice_public_expected =
        hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
            .expect("alice public must decode");
    let bob_public_expected =
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            .expect("bob public must decode");
    let shared_expected =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
            .expect("shared secret must decode");

    let alice_public = x25519_dalek::x25519(
        alice_secret
            .as_slice()
            .try_into()
            .expect("alice secret length must be 32"),
        x25519_dalek::X25519_BASEPOINT_BYTES,
    );
    let bob_public = x25519_dalek::x25519(
        bob_secret
            .as_slice()
            .try_into()
            .expect("bob secret length must be 32"),
        x25519_dalek::X25519_BASEPOINT_BYTES,
    );
    assert_eq!(alice_public, alice_public_expected.as_slice());
    assert_eq!(bob_public, bob_public_expected.as_slice());

    let shared_from_api =
        derive_x25519_shared_secret(&alice_secret, &bob_public_expected).expect("derive must work");
    assert_eq!(*shared_from_api, shared_expected);
}
