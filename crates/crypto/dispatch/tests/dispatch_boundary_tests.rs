// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(all(
    feature = "native",
    feature = "ed25519",
    feature = "ml-dsa-44",
    feature = "ml-dsa-65",
    feature = "ml-dsa-87",
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "secp256k1",
    feature = "x25519",
    feature = "x-wing"
))]

use crypto_core::Algorithm;
use crypto_dispatch::{
    derive_shared_secret, generate_keypair, kem_decapsulate, kem_encapsulate, sign, verify,
};

const MESSAGE: &[u8] = b"dispatch boundary validation";

#[test]
fn dispatch_rejects_malformed_signature_key_and_signature_lengths() {
    for algorithm in SIGNATURE_ALGORITHMS.iter().copied() {
        let (public_key, secret_key) =
            generate_keypair(algorithm).expect("signature keypair generation must succeed");
        let signature = sign(algorithm, &secret_key, MESSAGE).expect("signature must succeed");

        assert!(
            sign(algorithm, &[], MESSAGE).is_err(),
            "{algorithm:?} must reject an empty signing key"
        );
        assert!(
            verify(algorithm, &[], MESSAGE, &signature).is_err(),
            "{algorithm:?} must reject an empty verification key"
        );
        assert!(
            verify(algorithm, &public_key, MESSAGE, &[]).is_err(),
            "{algorithm:?} must reject an empty signature"
        );
    }
}

#[test]
fn dispatch_rejects_malformed_key_agreement_lengths() {
    for algorithm in KEY_AGREEMENT_ALGORITHMS.iter().copied() {
        let (public_key, secret_key) =
            generate_keypair(algorithm).expect("key agreement keypair generation must succeed");

        assert!(
            derive_shared_secret(algorithm, &[], &public_key).is_err(),
            "{algorithm:?} must reject an empty secret key"
        );
        assert!(
            derive_shared_secret(algorithm, &secret_key, &[]).is_err(),
            "{algorithm:?} must reject an empty public key"
        );
    }
}

#[test]
fn dispatch_rejects_malformed_kem_key_and_ciphertext_lengths() {
    for algorithm in KEM_ALGORITHMS.iter().copied() {
        let (public_key, secret_key) =
            generate_keypair(algorithm).expect("KEM keypair generation must succeed");
        let (_shared_secret, ciphertext) =
            kem_encapsulate(algorithm, &public_key).expect("KEM encapsulation must succeed");

        assert!(
            kem_encapsulate(algorithm, &[]).is_err(),
            "{algorithm:?} must reject an empty public key"
        );
        assert!(
            kem_decapsulate(algorithm, &[], &secret_key).is_err(),
            "{algorithm:?} must reject an empty ciphertext"
        );
        assert!(
            kem_decapsulate(algorithm, &ciphertext, &[]).is_err(),
            "{algorithm:?} must reject an empty secret key"
        );
    }
}

const SIGNATURE_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::P256,
    Algorithm::P384,
    Algorithm::P521,
    Algorithm::Secp256k1,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
];

const KEY_AGREEMENT_ALGORITHMS: &[Algorithm] = &[
    Algorithm::P256,
    Algorithm::P384,
    Algorithm::P521,
    Algorithm::X25519,
];

const KEM_ALGORITHMS: &[Algorithm] = &[
    Algorithm::MlKem512,
    Algorithm::MlKem768,
    Algorithm::MlKem1024,
    Algorithm::XWing768,
];
