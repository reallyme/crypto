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
    derive_shared_secret, generate_keypair, kem_decapsulate, kem_encapsulate,
    public_key_to_multikey, sign, validate_verification_method_multikey, verify,
};

//
// -----------------------------------------------------------------------------
// Keypair generation (ALL algorithms)
// -----------------------------------------------------------------------------

#[test]
fn all_algorithms_can_generate_keypairs() {
    for alg in [
        Algorithm::Ed25519,
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
        Algorithm::Secp256k1,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::X25519,
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
        Algorithm::XWing768,
        Algorithm::XWing1024,
    ] {
        let (public, secret) = generate_keypair(alg).unwrap();
        assert!(!public.is_empty(), "{alg:?} public key empty");
        assert!(!secret.is_empty(), "{alg:?} secret key empty");
    }
}

//
// -----------------------------------------------------------------------------
// Signing algorithms
// -----------------------------------------------------------------------------

#[test]
fn signing_algorithms_roundtrip() {
    let message = b"dispatch signing test";

    for alg in [
        Algorithm::Ed25519,
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
        Algorithm::Secp256k1,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
    ] {
        let (public, secret) = generate_keypair(alg).unwrap();
        let sig = sign(alg, &secret, message).unwrap();
        verify(alg, &public, message, &sig).unwrap();
    }
}

#[test]
fn signing_rejects_non_signing_algorithms() {
    let msg = b"invalid sign";

    for alg in [
        Algorithm::X25519,
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
        Algorithm::XWing768,
        Algorithm::XWing1024,
    ] {
        let (_pk, sk) = generate_keypair(alg).unwrap();
        assert!(sign(alg, &sk, msg).is_err(), "{alg:?} should not sign");
    }
}

//
// -----------------------------------------------------------------------------
// ECDH / DH key agreement
// -----------------------------------------------------------------------------

#[test]
fn p256_shared_secret_matches() {
    let (pk1, sk1) = generate_keypair(Algorithm::P256).unwrap();
    let (pk2, sk2) = generate_keypair(Algorithm::P256).unwrap();

    let s1 = derive_shared_secret(Algorithm::P256, &sk1, &pk2).unwrap();
    let s2 = derive_shared_secret(Algorithm::P256, &sk2, &pk1).unwrap();

    assert_eq!(s1, s2, "P-256 shared secrets must match");
    assert_eq!(s1.len(), 32);
}

#[test]
fn x25519_shared_secret_matches() {
    let (pk1, sk1) = generate_keypair(Algorithm::X25519).unwrap();
    let (pk2, sk2) = generate_keypair(Algorithm::X25519).unwrap();

    let s1 = derive_shared_secret(Algorithm::X25519, &sk1, &pk2).unwrap();
    let s2 = derive_shared_secret(Algorithm::X25519, &sk2, &pk1).unwrap();

    assert_eq!(s1, s2, "X25519 shared secrets must match");
}

#[test]
fn dh_rejects_non_key_agreement_algorithms() {
    let (pk, sk) = generate_keypair(Algorithm::Ed25519).unwrap();

    assert!(derive_shared_secret(Algorithm::Ed25519, &sk, &pk).is_err());
}

//
// -----------------------------------------------------------------------------
// ML-KEM encapsulation
// -----------------------------------------------------------------------------

#[test]
fn ml_kem_encapsulation_roundtrip() {
    for alg in [
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
        Algorithm::XWing768,
        Algorithm::XWing1024,
    ] {
        let (pk, sk) = generate_keypair(alg).unwrap();

        let (shared_send, ct) = kem_encapsulate(alg, &pk).unwrap();
        let shared_recv = kem_decapsulate(alg, &ct, &sk).unwrap();

        assert_eq!(shared_send, shared_recv, "{alg:?} KEM secrets must match");
    }
}

#[test]
fn kem_rejects_non_kem_algorithms() {
    let (pk, _sk) = generate_keypair(Algorithm::Ed25519).unwrap();
    assert!(kem_encapsulate(Algorithm::Ed25519, &pk).is_err());
}

//
// -----------------------------------------------------------------------------
// Multikey + validation (ALL algorithms)
// -----------------------------------------------------------------------------

#[test]
fn all_algorithms_produce_valid_multikeys() {
    for alg in [
        Algorithm::Ed25519,
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
        Algorithm::Secp256k1,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::X25519,
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
    ] {
        let (public, _) = generate_keypair(alg).unwrap();
        let mk = public_key_to_multikey(alg, &public).unwrap();

        validate_verification_method_multikey(alg, "Multikey", &mk).unwrap();
    }
}

#[test]
fn multikey_validation_rejects_algorithm_mismatch() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    assert!(validate_verification_method_multikey(Algorithm::X25519, "Multikey", &mk,).is_err());
}

#[test]
fn multikey_validation_rejects_bad_binding() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    assert!(
        validate_verification_method_multikey(Algorithm::Ed25519, "SomeOtherBinding", &mk,)
            .is_err()
    );
}

#[test]
fn deterministic_signature_vectors_match_dispatch() {
    let ed_sk = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("ed25519 secret must decode");
    let ed_pk = hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
        .expect("ed25519 public must decode");
    let ed_msg =
        hex::decode("48656c6c6f2c204564323535313921").expect("ed25519 message must decode");
    let ed_sig = hex::decode(
        "b9949183e18ea0593117959085e0230ccf069ce895e69854f1df199b08226f659e25aaf14c4029d2b0e3d1344401609a324b2bfa8d87f93d8020bb6c287d7309",
    )
    .expect("ed25519 signature must decode");
    assert_eq!(
        sign(Algorithm::Ed25519, &ed_sk, &ed_msg).expect("ed25519 sign must succeed"),
        ed_sig
    );
    verify(Algorithm::Ed25519, &ed_pk, &ed_msg, &ed_sig).expect("ed25519 verify must succeed");

    let p256_sk = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("p256 secret must decode");
    let p256_pk = hex::decode("027a593180860c4037c83c12749845c8ee1424dd297fadcb895e358255d2c7d2b2")
        .expect("p256 public must decode");
    let p256_msg = hex::decode("48656c6c6f2c20502d32353621").expect("p256 message must decode");
    let p256_sig = hex::decode(
        "304402204bd4ee72b48883a4d1817e0371c66b6412117183794c6b220fb13590b7f980970220316c6251e714b87c65fd161dd1823e888b1c66d9075ff8cd7ade89d166e935de",
    )
    .expect("p256 signature must decode");
    assert_eq!(
        sign(Algorithm::P256, &p256_sk, &p256_msg).expect("p256 sign must succeed"),
        p256_sig
    );
    verify(Algorithm::P256, &p256_pk, &p256_msg, &p256_sig).expect("p256 verify must succeed");

    let k1_sk = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("secp256k1 secret must decode");
    let k1_pk = hex::decode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2")
        .expect("secp256k1 public must decode");
    let k1_msg =
        hex::decode("48656c6c6f2c20736563703235366b3121").expect("secp256k1 message must decode");
    let k1_sig = hex::decode(
        "ee3f9089351bd0d9c622d6d2668c491d257bd61f3d1d8ffa1cf237ed5c119069495b22b9ae98ef7474b8da5424b2a7fa44a2e5ee8dfd3e55ccebccb49b321380",
    )
    .expect("secp256k1 signature must decode");
    assert_eq!(
        sign(Algorithm::Secp256k1, &k1_sk, &k1_msg).expect("secp256k1 sign must succeed"),
        k1_sig
    );
    verify(Algorithm::Secp256k1, &k1_pk, &k1_msg, &k1_sig).expect("secp256k1 verify must succeed");
}

#[test]
fn x25519_rfc7748_vector_matches_dispatch() {
    let alice_secret =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .expect("alice secret must decode");
    let bob_public =
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            .expect("bob public must decode");
    let shared_expected =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
            .expect("shared secret must decode");

    let shared = derive_shared_secret(Algorithm::X25519, &alice_secret, &bob_public)
        .expect("dispatch derive must succeed");
    assert_eq!(*shared, shared_expected);
}
