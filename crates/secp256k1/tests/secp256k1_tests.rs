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
#![cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]

use crypto_core::{CryptoError, SignatureBackend, SignatureFailureKind, SignatureOperation};
use crypto_secp256k1::{
    decompress_secp256k1_public_key, derive_bip340_schnorr_public_key,
    generate_secp256k1_keypair_from_secret_key, sign_bip340_schnorr, sign_secp256k1,
    try_generate_secp256k1_keypair, verify_bip340_schnorr, verify_secp256k1,
};
use k256::elliptic_curve::ff::PrimeField;
use zeroize::Zeroizing;

type TestKeypair = (Vec<u8>, Zeroizing<Vec<u8>>);

fn assert_signature_error<T>(
    result: Result<T, CryptoError>,
    operation: SignatureOperation,
    kind: SignatureFailureKind,
) {
    assert!(matches!(
        result,
        Err(CryptoError::Signature {
            backend: SignatureBackend::Native,
            operation: actual_operation,
            kind: actual_kind,
        }) if actual_operation == operation && actual_kind == kind
    ));
}

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
fn key_sizes_are_correct() -> Result<(), CryptoError> {
    let (pk, sk) = try_generate_secp256k1_keypair().into_test_result()?;
    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 33);
    Ok(())
}

#[test]
fn secret_key_constructor_is_deterministic_and_rejects_zero() -> Result<(), CryptoError> {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let (public_a, secret_a) =
        generate_secp256k1_keypair_from_secret_key(&secret).into_test_result()?;
    let (public_b, secret_b) =
        generate_secp256k1_keypair_from_secret_key(&secret).into_test_result()?;

    assert_eq!(public_a, public_b);
    assert_eq!(secret_a, secret_b);
    assert_eq!(secret_a.as_slice(), secret.as_slice());
    assert!(matches!(
        generate_secp256k1_keypair_from_secret_key(&[0u8; 32]),
        Err(CryptoError::InvalidKey)
    ));

    let signature = sign_secp256k1(&secret_a, b"seeded secp256k1")?;
    verify_secp256k1(&signature, b"seeded secp256k1", &public_a)?;
    Ok(())
}

#[test]
fn sign_and_verify_roundtrip() -> Result<(), CryptoError> {
    let (pk, sk) = try_generate_secp256k1_keypair().into_test_result()?;
    let msg = b"secp256k1 test";

    let sig = sign_secp256k1(&sk, msg)?;
    verify_secp256k1(&sig, msg, &pk)?;
    Ok(())
}

#[test]
fn verification_fails_on_modified_message() -> Result<(), CryptoError> {
    let (pk, sk) = try_generate_secp256k1_keypair().into_test_result()?;
    let sig = sign_secp256k1(&sk, b"hello")?;

    assert_signature_error(
        verify_secp256k1(&sig, b"hell0", &pk),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );
    Ok(())
}

#[test]
fn verification_fails_on_modified_signature() -> Result<(), CryptoError> {
    let (pk, sk) = try_generate_secp256k1_keypair().into_test_result()?;
    let msg = b"test message";

    let mut sig = sign_secp256k1(&sk, msg)?;
    sig[0] ^= 0x01;
    assert_signature_error(
        verify_secp256k1(&sig, msg, &pk),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );
    Ok(())
}

#[test]
fn signature_does_not_verify_under_different_key() -> Result<(), CryptoError> {
    let (_pk1, sk1) = try_generate_secp256k1_keypair().into_test_result()?;
    let (pk2, _sk2) = try_generate_secp256k1_keypair().into_test_result()?;

    let msg = b"test message";
    let sig = sign_secp256k1(&sk1, msg)?;

    assert_signature_error(
        verify_secp256k1(&sig, msg, &pk2),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );
    Ok(())
}

#[test]
#[cfg(feature = "native")]
fn decompression_roundtrip() -> Result<(), CryptoError> {
    let (pk, _sk) = try_generate_secp256k1_keypair().into_test_result()?;
    let (x, y) = decompress_secp256k1_public_key(&pk)?;

    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);
    Ok(())
}

#[test]
fn signature_is_low_s() -> Result<(), CryptoError> {
    let (_pk, sk) = try_generate_secp256k1_keypair().into_test_result()?;
    let msg = b"low-s test";

    let sig = sign_secp256k1(&sk, msg)?;

    // s is second half of compact signature
    let s = &sig[32..64];

    // curve order n / 2 for secp256k1
    let half_n =
        hex_literal::hex!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

    assert!(s <= half_n.as_slice(), "signature S value is not low-S");
    Ok(())
}

#[test]
fn high_s_twin_is_rejected_with_typed_signature_error() -> Result<(), CryptoError> {
    let (public_key, secret_key) = try_generate_secp256k1_keypair().into_test_result()?;
    let message = b"high-S malleability boundary";
    let signature = sign_secp256k1(&secret_key, message)?;
    verify_secp256k1(&signature, message, &public_key)?;

    let scalar_bytes: [u8; 32] = signature[32..]
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let scalar = Option::<k256::Scalar>::from(k256::Scalar::from_repr(scalar_bytes.into()))
        .ok_or(CryptoError::InvalidKey)?;
    let mut malleated = signature.clone();
    malleated[32..].copy_from_slice(&(-scalar).to_bytes());

    assert!(matches!(
        verify_secp256k1(&malleated, message, &public_key),
        Err(CryptoError::Signature {
            kind: SignatureFailureKind::InvalidSignature,
            ..
        })
    ));
    Ok(())
}

#[test]
fn invalid_signature_length_is_rejected() -> Result<(), CryptoError> {
    let (pk, _sk) = try_generate_secp256k1_keypair().into_test_result()?;
    let msg = b"test";

    let bad_sig = vec![0u8; 10];
    assert_signature_error(
        verify_secp256k1(&bad_sig, msg, &pk),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );
    Ok(())
}

#[test]
fn invalid_public_key_is_rejected() {
    let msg = b"test";
    let sig = vec![0u8; 64];

    // wrong length
    let bad_pk = vec![0x02; 10];
    assert!(matches!(
        verify_secp256k1(&sig, msg, &bad_pk),
        Err(CryptoError::InvalidKey)
    ));

    // wrong prefix
    let mut bad_prefix = vec![0x04; 33];
    bad_prefix[0] = 0x04;
    assert!(matches!(
        verify_secp256k1(&sig, msg, &bad_prefix),
        Err(CryptoError::InvalidKey)
    ));
}

#[test]
fn invalid_secret_key_length_is_rejected() {
    let bad_sk = vec![0x11; 31];
    assert!(matches!(
        sign_secp256k1(&bad_sk, b"msg"),
        Err(CryptoError::InvalidKey)
    ));
}

#[test]
fn deterministic_vector_matches() {
    let secret = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("vector secret must decode");
    let public = hex::decode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2")
        .expect("vector public must decode");
    let message =
        hex::decode("48656c6c6f2c20736563703235366b3121").expect("vector message must decode");
    let signature = hex::decode(
        "ee3f9089351bd0d9c622d6d2668c491d257bd61f3d1d8ffa1cf237ed5c119069495b22b9ae98ef7474b8da5424b2a7fa44a2e5ee8dfd3e55ccebccb49b321380",
    )
    .expect("vector signature must decode");

    let produced = sign_secp256k1(&secret, &message).expect("vector signing must succeed");
    assert_eq!(produced, signature);

    verify_secp256k1(&signature, &message, &public).expect("vector verify must succeed");
}

#[test]
fn bip340_schnorr_official_vector_zero_matches() -> Result<(), CryptoError> {
    let secret =
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let public =
        hex_literal::hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    let aux_rand =
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
    let message =
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
    let expected_signature = hex_literal::hex!(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215\
         25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    );

    let derived_public = derive_bip340_schnorr_public_key(&secret)?;
    assert_eq!(derived_public, public);

    let signature = sign_bip340_schnorr(&secret, &message, &aux_rand)?;
    assert_eq!(signature, expected_signature);
    verify_bip340_schnorr(&signature, &message, &public)?;

    Ok(())
}

#[test]
fn bip340_schnorr_rejects_tampering() -> Result<(), CryptoError> {
    let secret =
        hex_literal::hex!("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let public =
        hex_literal::hex!("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    let aux_rand =
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000001");
    let message =
        hex_literal::hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    let signature = sign_bip340_schnorr(&secret, &message, &aux_rand)?;

    let mut tampered_message = message;
    tampered_message[0] ^= 0x01;
    assert_signature_error(
        verify_bip340_schnorr(&signature, &tampered_message, &public),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );

    let mut tampered_signature = signature;
    tampered_signature[0] ^= 0x01;
    assert_signature_error(
        verify_bip340_schnorr(&tampered_signature, &message, &public),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );

    Ok(())
}

#[test]
fn bip340_schnorr_rejects_malformed_lengths() -> Result<(), CryptoError> {
    let secret = [0x03u8; 32];
    let aux_rand = [0u8; 32];
    let message = [0u8; 32];
    let public = derive_bip340_schnorr_public_key(&secret)?;
    let signature = sign_bip340_schnorr(&secret, &message, &aux_rand)?;

    assert!(matches!(
        derive_bip340_schnorr_public_key(&secret[1..]),
        Err(CryptoError::InvalidKey)
    ));
    assert_signature_error(
        sign_bip340_schnorr(&secret, &message[1..], &aux_rand),
        SignatureOperation::Sign,
        SignatureFailureKind::InvalidMessage,
    );
    assert_signature_error(
        sign_bip340_schnorr(&secret, &message, &aux_rand[1..]),
        SignatureOperation::Sign,
        SignatureFailureKind::InvalidMessage,
    );
    assert_signature_error(
        verify_bip340_schnorr(&signature[1..], &message, &public),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidSignature,
    );
    assert_signature_error(
        verify_bip340_schnorr(&signature, &message[1..], &public),
        SignatureOperation::Verify,
        SignatureFailureKind::InvalidMessage,
    );
    assert!(matches!(
        verify_bip340_schnorr(&signature, &message, &public[1..]),
        Err(CryptoError::InvalidKey)
    ));

    Ok(())
}
