// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Direct SHA-256 digest signing tests shared by the native and WASM lanes.

#![allow(missing_docs)]
#![cfg(any(feature = "native", feature = "wasm"))]

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use crypto_p256::{
    generate_p256_keypair_from_secret_key, p256_ecdsa_der_to_jose_signature,
    p256_ecdsa_jose_signature_to_der, sign_p256_der_prehash, sign_p256_digest_der,
    verify_p256_digest_der, P256_SECRET_KEY_LEN, P256_SHA256_DIGEST_LEN,
};
use hex_literal::hex;
use p256::ecdsa::Signature as P256Signature;
use sha2::{Digest, Sha256};

const SECRET_KEY: [u8; P256_SECRET_KEY_LEN] =
    hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const MESSAGE: &[u8] = b"Hello, P-256!";
const EXPECTED_DER: [u8; 70] = hex!(
    "304402204bd4ee72b48883a4d1817e0371c66b6412117183794c6b220fb13590b7f98097
     0220316c6251e714b87c65fd161dd1823e888b1c66d9075ff8cd7ade89d166e935de"
);
const P256_ORDER: [u8; 32] =
    hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

fn signature_error(operation: SignatureOperation, kind: SignatureFailureKind) -> CryptoError {
    CryptoError::Signature {
        backend: expected_backend(),
        operation,
        kind,
    }
}

fn expected_backend() -> SignatureBackend {
    #[cfg(target_arch = "wasm32")]
    {
        SignatureBackend::Wasm
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SignatureBackend::Native
    }
}

fn subtract_scalar(left: &[u8; 32], right: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let left_byte = u16::from(left[index]);
        let right_byte = u16::from(right[index]);
        let subtrahend = right_byte + borrow;
        if left_byte >= subtrahend {
            output[index] = (left_byte - subtrahend).to_be_bytes()[1];
            borrow = 0;
        } else {
            output[index] = (256u16 + left_byte - subtrahend).to_be_bytes()[1];
            borrow = 1;
        }
    }
    output
}

#[test]
fn direct_digest_signature_is_deterministic_low_s_and_not_double_hashed() -> Result<(), CryptoError>
{
    let digest = Sha256::digest(MESSAGE);
    let signature = sign_p256_digest_der(&SECRET_KEY, digest.as_ref())?;
    let repeated = sign_p256_digest_der(&SECRET_KEY, digest.as_ref())?;
    let message_api_signature = sign_p256_der_prehash(&SECRET_KEY, MESSAGE)?;

    assert_eq!(signature, EXPECTED_DER);
    assert_eq!(repeated, EXPECTED_DER);
    assert_eq!(message_api_signature, EXPECTED_DER);

    let parsed = P256Signature::from_der(&signature).map_err(|_| {
        signature_error(
            SignatureOperation::Verify,
            SignatureFailureKind::InvalidSignature,
        )
    })?;
    assert_eq!(parsed.normalize_s(), parsed);
    Ok(())
}

#[test]
fn direct_digest_signature_verifies_in_selected_backend() -> Result<(), CryptoError> {
    let (public_key, _) = generate_p256_keypair_from_secret_key(&SECRET_KEY)?;
    let digest = Sha256::digest(MESSAGE);
    let signature = sign_p256_digest_der(&SECRET_KEY, digest.as_ref())?;

    verify_p256_digest_der(&signature, digest.as_ref(), &public_key)
}

#[test]
fn signing_rejects_invalid_secret_and_digest_lengths_with_typed_errors() {
    let valid_digest = [0x5au8; P256_SHA256_DIGEST_LEN];
    for invalid_secret in [&[][..], &[0u8; 31], &[0u8; 33]] {
        assert_eq!(
            sign_p256_digest_der(invalid_secret, &valid_digest),
            Err(signature_error(
                SignatureOperation::Sign,
                SignatureFailureKind::InvalidPrivateKey,
            ))
        );
    }
    assert_eq!(
        sign_p256_digest_der(&[0u8; P256_SECRET_KEY_LEN], &valid_digest),
        Err(signature_error(
            SignatureOperation::Sign,
            SignatureFailureKind::InvalidPrivateKey,
        ))
    );

    for invalid_digest in [&[][..], &[0u8; 31], &[0u8; 33]] {
        assert_eq!(
            sign_p256_digest_der(&SECRET_KEY, invalid_digest),
            Err(signature_error(
                SignatureOperation::Sign,
                SignatureFailureKind::InvalidMessage,
            ))
        );
    }
}

#[test]
fn verification_rejects_invalid_digest_lengths_with_typed_errors() -> Result<(), CryptoError> {
    let (public_key, _) = generate_p256_keypair_from_secret_key(&SECRET_KEY)?;
    let digest = Sha256::digest(MESSAGE);
    let signature = sign_p256_digest_der(&SECRET_KEY, digest.as_ref())?;

    for invalid_digest in [&[][..], &[0u8; 31], &[0u8; 33]] {
        assert_eq!(
            verify_p256_digest_der(&signature, invalid_digest, &public_key),
            Err(signature_error(
                SignatureOperation::Verify,
                SignatureFailureKind::InvalidMessage,
            ))
        );
    }
    Ok(())
}

#[test]
fn verification_rejects_tampered_digest_and_signature() -> Result<(), CryptoError> {
    let (public_key, _) = generate_p256_keypair_from_secret_key(&SECRET_KEY)?;
    let digest = Sha256::digest(MESSAGE);
    let signature = sign_p256_digest_der(&SECRET_KEY, digest.as_ref())?;
    let expected_error = signature_error(
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );

    let mut tampered_digest = digest;
    tampered_digest[0] ^= 0x80;
    assert_eq!(
        verify_p256_digest_der(&signature, tampered_digest.as_ref(), &public_key),
        Err(expected_error.clone())
    );

    let mut tampered_signature = signature;
    let final_index = tampered_signature
        .len()
        .checked_sub(1)
        .ok_or_else(|| expected_error.clone())?;
    tampered_signature[final_index] ^= 0x01;
    assert_eq!(
        verify_p256_digest_der(&tampered_signature, digest.as_ref(), &public_key),
        Err(expected_error)
    );
    Ok(())
}

#[test]
fn canonical_digest_verifier_rejects_high_s_twin() -> Result<(), CryptoError> {
    let (public_key, _) = generate_p256_keypair_from_secret_key(&SECRET_KEY)?;
    let digest = Sha256::digest(MESSAGE);
    let signature = sign_p256_digest_der(&SECRET_KEY, digest.as_ref())?;
    let mut compact = p256_ecdsa_der_to_jose_signature(&signature)?;
    let high_s = subtract_scalar(&P256_ORDER, &compact[32..]);
    compact[32..].copy_from_slice(&high_s);
    let high_s_der = p256_ecdsa_jose_signature_to_der(&compact)?;

    assert_eq!(
        verify_p256_digest_der(&high_s_der, digest.as_ref(), &public_key),
        Err(signature_error(
            SignatureOperation::Verify,
            SignatureFailureKind::InvalidSignature,
        ))
    );
    Ok(())
}
