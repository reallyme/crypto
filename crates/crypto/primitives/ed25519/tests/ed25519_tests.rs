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
use crypto_ed25519::*;
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

fn parse_vector_hex(contents: &str) -> String {
    contents
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(str::trim)
        .collect::<String>()
}

#[test]
fn keygen_produces_correct_sizes() -> Result<(), CryptoError> {
    let (pubkey, privkey) = generate_ed25519_keypair().into_test_result()?;
    assert_eq!(pubkey.len(), 32);
    assert_eq!(privkey.len(), 32);
    Ok(())
}

#[test]
fn seeded_keypair_is_deterministic_and_signs() -> Result<(), CryptoError> {
    let seed = [7u8; 32];
    let (pubkey_a, privkey_a) = generate_ed25519_keypair_from_seed(&seed).into_test_result()?;
    let (pubkey_b, privkey_b) = generate_ed25519_keypair_from_seed(&seed).into_test_result()?;

    assert_eq!(pubkey_a, pubkey_b);
    assert_eq!(privkey_a, privkey_b);
    assert_eq!(privkey_a.as_slice(), seed.as_slice());

    let signature = sign_ed25519(&privkey_a, b"seeded ed25519")?;
    verify_ed25519(&pubkey_a, b"seeded ed25519", &signature)?;

    let (pubkey_c, _privkey_c) =
        generate_ed25519_keypair_from_seed(&[8u8; 32]).into_test_result()?;
    assert_ne!(pubkey_a, pubkey_c);
    Ok(())
}

#[test]
fn sign_and_verify_roundtrip() -> Result<(), CryptoError> {
    let (pubkey, privkey) = generate_ed25519_keypair().into_test_result()?;
    let msg = b"hello world";

    let sig = sign_ed25519(&privkey, msg)?;
    verify_ed25519(&pubkey, msg, &sig)?;
    Ok(())
}

#[test]
fn verify_fails_for_modified_message() -> Result<(), CryptoError> {
    let (pubkey, privkey) = generate_ed25519_keypair().into_test_result()?;
    let msg = b"hello world";
    let sig = sign_ed25519(&privkey, msg)?;

    let bad_msg = b"h3llo world";

    assert!(verify_ed25519(&pubkey, bad_msg, &sig).is_err());
    Ok(())
}

#[test]
fn verify_fails_closed_for_modified_message() -> Result<(), CryptoError> {
    let (pubkey, privkey) = generate_ed25519_keypair().into_test_result()?;
    let sig = sign_ed25519(&privkey, b"hello world")?;

    verify_ed25519(&pubkey, b"hello world", &sig)?;
    assert!(verify_ed25519(&pubkey, b"h3llo world", &sig).is_err());
    Ok(())
}

#[test]
fn invalid_key_size_fails() {
    let result = verify_ed25519(&[1, 2, 3], b"msg", &[0u8; 64]);
    assert!(result.is_err());
}

#[test]
fn signature_does_not_verify_under_different_key() -> Result<(), CryptoError> {
    let (_pk1, sk1) = generate_ed25519_keypair().into_test_result()?;
    let (pk2, _sk2) = generate_ed25519_keypair().into_test_result()?;

    let msg = b"hello world";
    let sig = sign_ed25519(&sk1, msg)?;

    assert!(verify_ed25519(&pk2, msg, &sig).is_err());
    Ok(())
}

#[test]
fn verify_fails_for_modified_signature() -> Result<(), CryptoError> {
    let (pubkey, privkey) = generate_ed25519_keypair().into_test_result()?;
    let msg = b"hello world";

    let mut sig = sign_ed25519(&privkey, msg)?;
    sig[0] ^= 0x01;

    assert!(verify_ed25519(&pubkey, msg, &sig).is_err());
    Ok(())
}

#[test]
fn invalid_signature_size_fails() -> Result<(), CryptoError> {
    let (pubkey, _privkey) = generate_ed25519_keypair().into_test_result()?;

    let bad_sig = vec![0u8; 10]; // wrong size
    let result = verify_ed25519(&pubkey, b"msg", &bad_sig);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn signatures_are_deterministic() -> Result<(), CryptoError> {
    let (_pk, sk) = generate_ed25519_keypair().into_test_result()?;
    let msg = b"same message";

    let sig1 = sign_ed25519(&sk, msg)?;
    let sig2 = sign_ed25519(&sk, msg)?;

    assert_eq!(sig1, sig2);
    Ok(())
}

#[test]
fn expanded_private_key_works() -> Result<(), CryptoError> {
    let (pubkey, privkey) = generate_ed25519_keypair().into_test_result()?;

    // simulate expanded key: seed || pubkey
    let mut expanded = Vec::with_capacity(64);
    expanded.extend_from_slice(&privkey);
    expanded.extend_from_slice(&pubkey);

    let msg = b"hello expanded key";

    let sig = sign_ed25519(&expanded, msg)?;
    verify_ed25519(&pubkey, msg, &sig)?;
    Ok(())
}

#[test]
fn deterministic_vector_matches() {
    let seed = hex::decode(parse_vector_hex(include_str!(
        "vectors/ed25519_seed.hex.rs"
    )))
    .expect("valid seed vector");
    let public = hex::decode(parse_vector_hex(include_str!(
        "vectors/ed25519_public.hex.rs"
    )))
    .expect("valid public vector");
    let message = hex::decode(parse_vector_hex(include_str!(
        "vectors/ed25519_message.hex.rs"
    )))
    .expect("valid message vector");
    let signature = hex::decode(parse_vector_hex(include_str!(
        "vectors/ed25519_signature.hex.rs"
    )))
    .expect("valid signature vector");

    let generated = sign_ed25519(&seed, &message).expect("vector signing must succeed");
    assert_eq!(generated, signature);

    verify_ed25519(&public, &message, &signature).expect("vector verify must succeed");
}

#[test]
fn malformed_expanded_private_key_length_is_rejected() {
    let malformed = vec![0xAB; 63];
    let err = sign_ed25519(&malformed, b"msg");
    assert!(err.is_err());
}
