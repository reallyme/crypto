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
use crypto_p256::*;

#[test]
fn key_sizes_are_correct() -> Result<(), CryptoError> {
    let (pk, sk) = generate_p256_keypair()?;
    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 33); // compressed SEC1
    Ok(())
}

#[test]
fn secret_key_constructor_is_deterministic_and_rejects_zero() -> Result<(), CryptoError> {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let (public_a, secret_a) = generate_p256_keypair_from_secret_key(&secret)?;
    let (public_b, secret_b) = generate_p256_keypair_from_secret_key(&secret)?;

    assert_eq!(public_a, public_b);
    assert_eq!(secret_a, secret_b);
    assert_eq!(secret_a.as_slice(), secret.as_slice());
    assert!(generate_p256_keypair_from_secret_key(&[0u8; 32]).is_err());

    let signature = sign_p256_der_prehash(&secret_a, b"seeded p256")?;
    verify_p256_der_prehash(&signature, b"seeded p256", &public_a)?;
    Ok(())
}

#[test]
fn sign_and_verify_roundtrip() -> Result<(), CryptoError> {
    let (pk, sk) = generate_p256_keypair()?;
    let msg = b"p256 test";

    let sig = sign_p256_der_prehash(&sk, msg)?;
    verify_p256_der_prehash(&sig, msg, &pk)?;
    Ok(())
}

#[test]
fn verification_fails_on_modified_message() -> Result<(), CryptoError> {
    let (pk, sk) = generate_p256_keypair()?;
    let sig = sign_p256_der_prehash(&sk, b"hello")?;

    assert!(verify_p256_der_prehash(&sig, b"hell0", &pk).is_err());
    Ok(())
}

#[test]
fn signature_helper_fails_closed_on_modified_message() -> Result<(), CryptoError> {
    let (pk, sk) = generate_p256_keypair()?;
    let sig = sign_p256_der_prehash(&sk, b"hello")?;

    verify_p256_der_prehash(&sig, b"hello", &pk)?;
    assert!(verify_p256_der_prehash(&sig, b"hell0", &pk).is_err());
    Ok(())
}

#[test]
fn compression_roundtrip() -> Result<(), CryptoError> {
    let (pk, _sk) = generate_p256_keypair()?;
    let uncompressed = decompress_p256(&pk)?;
    let recompressed = compress_p256(&uncompressed)?;
    assert_eq!(pk, recompressed);
    Ok(())
}

#[test]
fn ecdh_shared_secret_matches_for_both_participants() -> Result<(), CryptoError> {
    let (alice_public, alice_secret) = generate_p256_keypair()?;
    let (bob_public, bob_secret) = generate_p256_keypair()?;

    let alice_shared = derive_p256_shared_secret(&alice_secret, &bob_public)?;
    let bob_shared = derive_p256_shared_secret(&bob_secret, &alice_public)?;

    assert_eq!(alice_shared, bob_shared);
    assert_eq!(alice_shared.len(), 32);
    assert_ne!(*alice_shared, vec![0u8; 32]);
    Ok(())
}

#[test]
fn ecdh_accepts_uncompressed_public_key() -> Result<(), CryptoError> {
    let (alice_public, alice_secret) = generate_p256_keypair()?;
    let (bob_public, bob_secret) = generate_p256_keypair()?;
    let bob_public_uncompressed = decompress_p256(&bob_public)?;
    let alice_shared = derive_p256_shared_secret(&alice_secret, &bob_public_uncompressed)?;
    let bob_shared = derive_p256_shared_secret(&bob_secret, &alice_public)?;

    assert_eq!(alice_shared, bob_shared);
    Ok(())
}

#[test]
fn invalid_public_key_is_rejected() {
    let msg = b"test message";
    let bogus_pk = vec![0x04; 10]; // wrong length

    let sig = vec![0x30, 0x44]; // fake DER header

    assert!(verify_p256_der_prehash(&sig, msg, &bogus_pk).is_err());
}

#[test]
fn ecdh_rejects_invalid_keys() -> Result<(), CryptoError> {
    let (public, secret) = generate_p256_keypair()?;
    let bad_secret = [0u8; 31];
    let bad_public = [0x04u8; 10];

    assert!(derive_p256_shared_secret(&bad_secret, &public).is_err());
    assert!(derive_p256_shared_secret(&secret, &bad_public).is_err());
    Ok(())
}

#[test]
fn invalid_der_signature_is_rejected() -> Result<(), CryptoError> {
    let (pk, _sk) = generate_p256_keypair()?;
    let msg = b"test message";

    // Not valid DER
    let bogus_sig = vec![0x01, 0x02, 0x03, 0x04];

    assert!(verify_p256_der_prehash(&bogus_sig, msg, &pk).is_err());
    Ok(())
}

#[test]
fn verification_fails_on_modified_signature() -> Result<(), CryptoError> {
    let (pk, sk) = generate_p256_keypair()?;
    let msg = b"test message";

    let mut sig = sign_p256_der_prehash(&sk, msg)?;
    sig[0] ^= 0x01;
    assert!(verify_p256_der_prehash(&sig, msg, &pk).is_err());
    Ok(())
}

#[test]
fn signature_does_not_verify_under_different_key() -> Result<(), CryptoError> {
    let (_pk1, sk1) = generate_p256_keypair()?;
    let (pk2, _sk2) = generate_p256_keypair()?;

    let msg = b"test message";
    let sig = sign_p256_der_prehash(&sk1, msg)?;

    assert!(verify_p256_der_prehash(&sig, msg, &pk2).is_err());
    Ok(())
}

#[test]
fn verify_accepts_uncompressed_public_key() -> Result<(), CryptoError> {
    let (pk_compressed, sk) = generate_p256_keypair()?;
    let pk_uncompressed = decompress_p256(&pk_compressed)?;

    let msg = b"p256 test";
    let sig = sign_p256_der_prehash(&sk, msg)?;

    verify_p256_der_prehash(&sig, msg, &pk_uncompressed)?;
    Ok(())
}

#[test]
fn invalid_secret_key_is_rejected() {
    let bad_sk = vec![0u8; 10];
    let msg = b"test";

    assert!(sign_p256_der_prehash(&bad_sk, msg).is_err());
}

#[test]
fn deterministic_vector_matches() {
    let secret = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("vector secret must decode");
    let public = hex::decode("027a593180860c4037c83c12749845c8ee1424dd297fadcb895e358255d2c7d2b2")
        .expect("vector public must decode");
    let message = hex::decode("48656c6c6f2c20502d32353621").expect("vector message must decode");
    let signature = hex::decode(
        "304402204bd4ee72b48883a4d1817e0371c66b6412117183794c6b220fb13590b7f980970220316c6251e714b87c65fd161dd1823e888b1c66d9075ff8cd7ade89d166e935de",
    )
    .expect("vector signature must decode");

    let produced = sign_p256_der_prehash(&secret, &message).expect("vector signing must succeed");
    assert_eq!(produced, signature);

    verify_p256_der_prehash(&signature, &message, &public).expect("vector verify must succeed");
}
