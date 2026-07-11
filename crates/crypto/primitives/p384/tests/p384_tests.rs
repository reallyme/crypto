// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_core::CryptoError;
use crypto_p384::{
    compress_p384, decompress_p384, generate_p384_keypair, generate_p384_keypair_from_secret_key,
    sign_p384_der_prehash, verify_p384_der_prehash, P384_PUBLIC_KEY_COMPRESSED_LEN,
    P384_PUBLIC_KEY_UNCOMPRESSED_LEN, P384_SECRET_KEY_LEN,
};

#[test]
fn key_sizes_are_correct() {
    let (public_key, secret_key) = generate_p384_keypair();
    assert_eq!(secret_key.len(), P384_SECRET_KEY_LEN);
    assert_eq!(public_key.len(), P384_PUBLIC_KEY_COMPRESSED_LEN);
}

#[test]
fn secret_key_constructor_is_deterministic_and_rejects_zero() -> Result<(), CryptoError> {
    let mut secret = [0u8; 48];
    secret[47] = 1;
    let (public_a, secret_a) = generate_p384_keypair_from_secret_key(&secret)?;
    let (public_b, secret_b) = generate_p384_keypair_from_secret_key(&secret)?;

    assert_eq!(public_a, public_b);
    assert_eq!(secret_a, secret_b);
    assert_eq!(secret_a.as_slice(), secret.as_slice());
    assert!(generate_p384_keypair_from_secret_key(&[0u8; 48]).is_err());

    let signature = sign_p384_der_prehash(&secret_a, b"seeded p384")?;
    verify_p384_der_prehash(&signature, b"seeded p384", &public_a)?;
    Ok(())
}

#[test]
fn sign_and_verify_roundtrip() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p384_keypair();
    let message = b"p384 test";
    let signature = sign_p384_der_prehash(&secret_key, message)?;

    verify_p384_der_prehash(&signature, message, &public_key)?;
    Ok(())
}

#[test]
fn verification_fails_on_modified_message() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p384_keypair();
    let signature = sign_p384_der_prehash(&secret_key, b"hello")?;

    assert!(verify_p384_der_prehash(&signature, b"hell0", &public_key).is_err());
    Ok(())
}

#[test]
fn compression_roundtrip() -> Result<(), CryptoError> {
    let (compressed, _secret_key) = generate_p384_keypair();
    let uncompressed = decompress_p384(&compressed)?;
    let recompressed = compress_p384(&uncompressed)?;

    assert_eq!(uncompressed.len(), P384_PUBLIC_KEY_UNCOMPRESSED_LEN);
    assert_eq!(compressed, recompressed);
    Ok(())
}

#[test]
fn verify_accepts_uncompressed_public_key() -> Result<(), CryptoError> {
    let (compressed, secret_key) = generate_p384_keypair();
    let uncompressed = decompress_p384(&compressed)?;
    let message = b"p384 uncompressed";
    let signature = sign_p384_der_prehash(&secret_key, message)?;

    verify_p384_der_prehash(&signature, message, &uncompressed)?;
    Ok(())
}

#[test]
fn invalid_inputs_are_rejected() {
    assert!(sign_p384_der_prehash(&[0u8; 10], b"message").is_err());
    assert!(verify_p384_der_prehash(&[0x30, 0x00], b"message", &[0x04; 10]).is_err());
    assert!(compress_p384(&[0x04; 10]).is_err());
    assert!(decompress_p384(&[0x02; 10]).is_err());
}

#[test]
fn signature_does_not_verify_under_different_key() -> Result<(), CryptoError> {
    let (_public_key_1, secret_key_1) = generate_p384_keypair();
    let (public_key_2, _secret_key_2) = generate_p384_keypair();
    let message = b"p384 wrong key";
    let signature = sign_p384_der_prehash(&secret_key_1, message)?;

    assert!(verify_p384_der_prehash(&signature, message, &public_key_2).is_err());
    Ok(())
}

#[test]
fn verification_fails_on_modified_signature() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p384_keypair();
    let message = b"p384 tamper";
    let mut signature = sign_p384_der_prehash(&secret_key, message)?;
    signature[0] ^= 0x01;
    assert!(verify_p384_der_prehash(&signature, message, &public_key).is_err());
    Ok(())
}
