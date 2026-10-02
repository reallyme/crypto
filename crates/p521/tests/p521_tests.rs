// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use crypto_p521::{
    compress_p521, compress_public_key, decompress_p521, decompress_public_key,
    derive_p521_shared_secret, generate_p521_keypair, generate_p521_keypair_from_secret_key,
    sign_p521_der_prehash, verify_p521_der_prehash, P521_PUBLIC_KEY_COMPRESSED_LEN,
    P521_PUBLIC_KEY_UNCOMPRESSED_LEN, P521_SECRET_KEY_LEN, P521_SHARED_SECRET_LEN,
};

#[test]
fn key_sizes_are_correct() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p521_keypair()?;
    assert_eq!(secret_key.len(), P521_SECRET_KEY_LEN);
    assert_eq!(public_key.len(), P521_PUBLIC_KEY_COMPRESSED_LEN);
    Ok(())
}

#[test]
fn secret_key_constructor_is_deterministic_and_rejects_zero() -> Result<(), CryptoError> {
    let mut secret = [0u8; 66];
    secret[65] = 1;
    let (public_a, secret_a) = generate_p521_keypair_from_secret_key(&secret)?;
    let (public_b, secret_b) = generate_p521_keypair_from_secret_key(&secret)?;

    assert_eq!(public_a, public_b);
    assert_eq!(secret_a, secret_b);
    assert_eq!(secret_a.as_slice(), secret.as_slice());
    assert!(matches!(
        generate_p521_keypair_from_secret_key(&[0u8; 66]),
        Err(CryptoError::InvalidKey)
    ));

    let signature = sign_p521_der_prehash(&secret_a, b"seeded p521")?;
    verify_p521_der_prehash(&signature, b"seeded p521", &public_a)?;
    Ok(())
}

#[test]
fn sign_and_verify_roundtrip() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p521_keypair()?;
    let message = b"p521 test";
    let signature = sign_p521_der_prehash(&secret_key, message)?;

    verify_p521_der_prehash(&signature, message, &public_key)?;
    Ok(())
}

#[test]
fn verification_fails_on_modified_message() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p521_keypair()?;
    let signature = sign_p521_der_prehash(&secret_key, b"hello")?;

    assert!(matches!(
        verify_p521_der_prehash(&signature, b"hell0", &public_key),
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    ));
    Ok(())
}

#[test]
fn compression_roundtrip() -> Result<(), CryptoError> {
    let (compressed, _secret_key) = generate_p521_keypair()?;
    let uncompressed = decompress_p521(&compressed)?;
    let recompressed = compress_p521(&uncompressed)?;

    assert_eq!(uncompressed.len(), P521_PUBLIC_KEY_UNCOMPRESSED_LEN);
    assert_eq!(compressed, recompressed);
    Ok(())
}

#[test]
fn compression_helpers_reject_wrong_sec1_shapes() -> Result<(), CryptoError> {
    let (compressed, _secret_key) = generate_p521_keypair()?;
    let uncompressed = decompress_p521(&compressed)?;

    assert!(matches!(
        compress_p521(&compressed),
        Err(CryptoError::InvalidKey)
    ));
    assert!(matches!(
        decompress_p521(&uncompressed),
        Err(CryptoError::InvalidKey)
    ));

    let mut wrong_compressed_prefix = compressed;
    wrong_compressed_prefix[0] = 0x04;
    assert!(matches!(
        decompress_p521(&wrong_compressed_prefix),
        Err(CryptoError::InvalidKey)
    ));

    let mut wrong_uncompressed_prefix = uncompressed;
    wrong_uncompressed_prefix[0] = 0x02;
    assert!(matches!(
        compress_p521(&wrong_uncompressed_prefix),
        Err(CryptoError::InvalidKey)
    ));
    Ok(())
}

#[test]
fn uniform_public_key_aliases_match_curve_specific_names() -> Result<(), CryptoError> {
    let (compressed, _secret_key) = generate_p521_keypair()?;
    let uncompressed = decompress_public_key(&compressed)?;

    assert_eq!(uncompressed, decompress_p521(&compressed)?);
    assert_eq!(
        compress_public_key(&uncompressed)?,
        compress_p521(&uncompressed)?
    );
    Ok(())
}

#[test]
fn verify_accepts_uncompressed_public_key() -> Result<(), CryptoError> {
    let (compressed, secret_key) = generate_p521_keypair()?;
    let uncompressed = decompress_p521(&compressed)?;
    let message = b"p521 uncompressed";
    let signature = sign_p521_der_prehash(&secret_key, message)?;

    verify_p521_der_prehash(&signature, message, &uncompressed)?;
    Ok(())
}

#[test]
fn ecdh_shared_secret_matches_for_both_parties() -> Result<(), CryptoError> {
    let (alice_public, alice_secret) = generate_p521_keypair()?;
    let (bob_public, bob_secret) = generate_p521_keypair()?;

    let alice_shared = derive_p521_shared_secret(&alice_secret, &bob_public)?;
    let bob_shared = derive_p521_shared_secret(&bob_secret, &alice_public)?;

    assert_eq!(alice_shared.len(), P521_SHARED_SECRET_LEN);
    assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
    Ok(())
}

#[test]
fn ecdh_accepts_uncompressed_public_key() -> Result<(), CryptoError> {
    let (alice_public, alice_secret) = generate_p521_keypair()?;
    let (bob_public, bob_secret) = generate_p521_keypair()?;
    let bob_public_uncompressed = decompress_p521(&bob_public)?;

    let alice_shared = derive_p521_shared_secret(&alice_secret, &bob_public_uncompressed)?;
    let bob_shared = derive_p521_shared_secret(&bob_secret, &alice_public)?;

    assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
    Ok(())
}

#[test]
fn invalid_inputs_are_rejected() -> Result<(), CryptoError> {
    assert!(matches!(
        sign_p521_der_prehash(&[0u8; 10], b"message"),
        Err(CryptoError::InvalidKey)
    ));
    assert!(matches!(
        verify_p521_der_prehash(&[0x30, 0x00], b"message", &[0x04; 10]),
        Err(CryptoError::InvalidKey)
    ));
    assert!(matches!(
        compress_p521(&[0x04; 10]),
        Err(CryptoError::InvalidKey)
    ));
    assert!(matches!(
        decompress_p521(&[0x02; 10]),
        Err(CryptoError::InvalidKey)
    ));
    let (public, secret) = generate_p521_keypair()?;
    assert!(matches!(
        derive_p521_shared_secret(&[0u8; 10], &public),
        Err(CryptoError::InvalidKey)
    ));
    assert!(matches!(
        derive_p521_shared_secret(&secret, &[0x02; 10]),
        Err(CryptoError::InvalidKey)
    ));
    Ok(())
}

#[test]
fn signature_does_not_verify_under_different_key() -> Result<(), CryptoError> {
    let (_public_key_1, secret_key_1) = generate_p521_keypair()?;
    let (public_key_2, _secret_key_2) = generate_p521_keypair()?;
    let message = b"p521 wrong key";
    let signature = sign_p521_der_prehash(&secret_key_1, message)?;

    assert!(matches!(
        verify_p521_der_prehash(&signature, message, &public_key_2),
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    ));
    Ok(())
}

#[test]
fn verification_fails_on_modified_signature() -> Result<(), CryptoError> {
    let (public_key, secret_key) = generate_p521_keypair()?;
    let message = b"p521 tamper";
    let mut signature = sign_p521_der_prehash(&secret_key, message)?;
    signature[0] ^= 0x01;
    assert!(matches!(
        verify_p521_der_prehash(&signature, message, &public_key),
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: SignatureOperation::Verify,
            kind: SignatureFailureKind::InvalidSignature,
        })
    ));
    Ok(())
}
