// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Complete key-management and signing parity for supported algorithms.

#![cfg(all(
    feature = "ed25519",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "secp256k1"
))]
#![allow(clippy::expect_used)]

use crypto_core::Algorithm;
use reallyme_crypto::operations::{OperationError, PrimitiveErrorReason};

const MESSAGE: &[u8] = b"complete signature parity";

struct SignatureCase {
    algorithm: Algorithm,
    secret_key: Vec<u8>,
    public_key_len: usize,
}

#[test]
fn every_signature_algorithm_derives_and_signs_with_primitive_parity() {
    for case in signature_cases() {
        let operation_key_pair = reallyme_crypto::operations::signature::derive_key_pair(
            case.algorithm,
            &case.secret_key,
        )
        .expect("operation derives deterministic keypair");
        let primitive_public_key = primitive_public_key(case.algorithm, &case.secret_key)
            .expect("test table contains a signature algorithm");

        assert_eq!(operation_key_pair.public_key, primitive_public_key);
        assert_eq!(&*operation_key_pair.secret_key, &case.secret_key);
        assert_eq!(operation_key_pair.public_key.len(), case.public_key_len);

        let operation_signature = reallyme_crypto::operations::signature::sign(
            case.algorithm,
            &operation_key_pair.secret_key,
            MESSAGE,
        )
        .expect("operation signs deterministic vector");
        let primitive_signature = primitive_signature(case.algorithm, &case.secret_key, MESSAGE);
        assert_eq!(operation_signature, primitive_signature);

        reallyme_crypto::operations::signature::verify(
            case.algorithm,
            &operation_key_pair.public_key,
            MESSAGE,
            &operation_signature,
        )
        .expect("operation verifies deterministic vector");

        let empty_message_signature = reallyme_crypto::operations::signature::sign(
            case.algorithm,
            &operation_key_pair.secret_key,
            &[],
        )
        .expect("empty messages remain valid signature inputs");
        reallyme_crypto::operations::signature::verify(
            case.algorithm,
            &operation_key_pair.public_key,
            &[],
            &empty_message_signature,
        )
        .expect("operation verifies an empty-message signature");
    }
}

#[test]
fn every_signature_algorithm_generates_usable_zeroizing_key_material() {
    for case in signature_cases() {
        let key_pair = reallyme_crypto::operations::signature::generate_key_pair(case.algorithm)
            .expect("operation generates keypair");
        assert_eq!(key_pair.public_key.len(), case.public_key_len);
        assert_eq!(key_pair.secret_key.len(), case.secret_key.len());

        let signature = reallyme_crypto::operations::signature::sign(
            case.algorithm,
            &key_pair.secret_key,
            MESSAGE,
        )
        .expect("generated key signs");
        reallyme_crypto::operations::signature::verify(
            case.algorithm,
            &key_pair.public_key,
            MESSAGE,
            &signature,
        )
        .expect("generated key verifies");
    }
}

#[test]
fn every_signature_algorithm_rejects_invalid_keys_and_tampering_with_typed_errors() {
    for case in signature_cases() {
        let short_secret = &case.secret_key[..case.secret_key.len() - 1];
        assert_eq!(
            derive_key_pair_error(case.algorithm, short_secret),
            Some(OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            })
        );
        assert_eq!(
            reallyme_crypto::operations::signature::sign(case.algorithm, short_secret, MESSAGE)
                .expect_err("short signing secret must fail"),
            OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            }
        );

        let key_pair = reallyme_crypto::operations::signature::derive_key_pair(
            case.algorithm,
            &case.secret_key,
        )
        .expect("operation derives keypair");
        let mut signature = reallyme_crypto::operations::signature::sign(
            case.algorithm,
            &key_pair.secret_key,
            MESSAGE,
        )
        .expect("operation signs");
        let last = signature
            .len()
            .checked_sub(1)
            .expect("supported signatures are non-empty");
        signature[last] ^= 0x01;

        assert_eq!(
            reallyme_crypto::operations::signature::verify(
                case.algorithm,
                &key_pair.public_key,
                MESSAGE,
                &signature,
            )
            .expect_err("tampered signature must fail"),
            OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            }
        );
        assert_eq!(
            reallyme_crypto::operations::signature::verify(
                case.algorithm,
                &key_pair.public_key,
                b"wrong message",
                &primitive_signature(case.algorithm, &case.secret_key, MESSAGE),
            )
            .expect_err("wrong message must fail"),
            OperationError::Primitive {
                reason: PrimitiveErrorReason::VerificationFailed,
            }
        );
        assert_eq!(
            reallyme_crypto::operations::signature::verify(
                case.algorithm,
                &[],
                MESSAGE,
                &primitive_signature(case.algorithm, &case.secret_key, MESSAGE),
            )
            .expect_err("invalid public key must fail"),
            OperationError::Primitive {
                reason: PrimitiveErrorReason::InvalidKey,
            }
        );
    }
}

#[test]
fn root_ed25519_and_secp256k1_key_management_use_the_operation_contract() {
    let ed_seed = [0x42; 32];
    let root_ed = reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(&ed_seed)
        .expect("root facade derives Ed25519 keypair");
    let operation_ed =
        reallyme_crypto::operations::signature::derive_key_pair(Algorithm::Ed25519, &ed_seed)
            .expect("operation derives Ed25519 keypair");
    assert_eq!(root_ed.0, operation_ed.public_key);
    assert_eq!(&*root_ed.1, &*operation_ed.secret_key);

    let secp_secret = [0x05; 32];
    let root_secp =
        reallyme_crypto::secp256k1::generate_secp256k1_keypair_from_secret_key(&secp_secret)
            .expect("root facade derives secp256k1 keypair");
    let operation_secp =
        reallyme_crypto::operations::signature::derive_key_pair(Algorithm::Secp256k1, &secp_secret)
            .expect("operation derives secp256k1 keypair");
    assert_eq!(root_secp.0, operation_secp.public_key);
    assert_eq!(&*root_secp.1, &*operation_secp.secret_key);
}

fn derive_key_pair_error(algorithm: Algorithm, secret_key: &[u8]) -> Option<OperationError> {
    reallyme_crypto::operations::signature::derive_key_pair(algorithm, secret_key).err()
}

fn signature_cases() -> Vec<SignatureCase> {
    let mut p521_secret = vec![0; 66];
    p521_secret[65] = 1;
    vec![
        SignatureCase {
            algorithm: Algorithm::Ed25519,
            secret_key: vec![0x42; 32],
            public_key_len: 32,
        },
        SignatureCase {
            algorithm: Algorithm::P256,
            secret_key: vec![0x01; 32],
            public_key_len: 33,
        },
        SignatureCase {
            algorithm: Algorithm::P384,
            secret_key: vec![0x01; 48],
            public_key_len: 49,
        },
        SignatureCase {
            algorithm: Algorithm::P521,
            secret_key: p521_secret,
            public_key_len: 67,
        },
        SignatureCase {
            algorithm: Algorithm::Secp256k1,
            secret_key: vec![0x05; 32],
            public_key_len: 33,
        },
    ]
}

fn primitive_public_key(algorithm: Algorithm, secret_key: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => {
            let seed = <&[u8; 32]>::try_from(secret_key).expect("Ed25519 seed length");
            Some(crypto_ed25519::generate_ed25519_keypair_from_seed(seed).0)
        }
        Algorithm::P256 => {
            let secret = <&[u8; 32]>::try_from(secret_key).expect("P-256 scalar length");
            Some(
                crypto_p256::generate_p256_keypair_from_secret_key(secret)
                    .expect("valid P-256 scalar")
                    .0,
            )
        }
        Algorithm::P384 => {
            let secret = <&[u8; 48]>::try_from(secret_key).expect("P-384 scalar length");
            Some(
                crypto_p384::generate_p384_keypair_from_secret_key(secret)
                    .expect("valid P-384 scalar")
                    .0,
            )
        }
        Algorithm::P521 => {
            let secret = <&[u8; 66]>::try_from(secret_key).expect("P-521 scalar length");
            Some(
                crypto_p521::generate_p521_keypair_from_secret_key(secret)
                    .expect("valid P-521 scalar")
                    .0,
            )
        }
        Algorithm::Secp256k1 => {
            let secret = <&[u8; 32]>::try_from(secret_key).expect("secp256k1 scalar length");
            Some(
                crypto_secp256k1::generate_secp256k1_keypair_from_secret_key(secret)
                    .expect("valid secp256k1 scalar")
                    .0,
            )
        }
        _ => None,
    }
}

fn primitive_signature(algorithm: Algorithm, secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let signature = match algorithm {
        Algorithm::Ed25519 => Some(crypto_ed25519::sign_ed25519(secret_key, message)),
        Algorithm::P256 => Some(crypto_p256::sign_p256_der_prehash(secret_key, message)),
        Algorithm::P384 => Some(crypto_p384::sign_p384_der_prehash(secret_key, message)),
        Algorithm::P521 => Some(crypto_p521::sign_p521_der_prehash(secret_key, message)),
        Algorithm::Secp256k1 => Some(crypto_secp256k1::sign_secp256k1(secret_key, message)),
        _ => None,
    }
    .expect("test table contains a signature algorithm");
    signature.expect("valid deterministic primitive signature")
}
