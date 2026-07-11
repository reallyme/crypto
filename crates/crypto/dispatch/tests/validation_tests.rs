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

use crypto_core::Algorithm;
use crypto_dispatch::{
    generate_keypair, public_key_to_multikey, validate_verification_method_multikey,
};

#[test]
fn x25519_verification_method_is_valid() {
    let (public, _) = generate_keypair(Algorithm::X25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::X25519, &public).unwrap();

    validate_verification_method_multikey(Algorithm::X25519, "Multikey", &mk)
        .expect("valid X25519 multikey");
}

#[test]
fn ml_kem_verification_method_is_valid() {
    let (public, _) = generate_keypair(Algorithm::MlKem1024).unwrap();
    let mk = public_key_to_multikey(Algorithm::MlKem1024, &public).unwrap();

    validate_verification_method_multikey(Algorithm::MlKem1024, "Multikey", &mk)
        .expect("valid ML-KEM-1024 multikey");
}

#[test]
fn ed25519_verification_method_is_valid() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    validate_verification_method_multikey(Algorithm::Ed25519, "Multikey", &mk)
        .expect("valid Ed25519 multikey");
}

#[test]
fn invalid_multikey_string_is_rejected() {
    let bad = "zthisisnotvalidmultikeydata";

    let err = validate_verification_method_multikey(Algorithm::X25519, "Multikey", bad);

    assert!(err.is_err());
}

#[test]
fn wrong_algorithm_is_rejected() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    let err = validate_verification_method_multikey(Algorithm::X25519, "Multikey", &mk);

    assert!(err.is_err());
}

#[test]
fn wrong_binding_type_is_rejected() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    let err = validate_verification_method_multikey(Algorithm::Ed25519, "SomeOtherKeyType", &mk);

    assert!(err.is_err());
}

#[test]
fn wrong_key_length_is_rejected() {
    // valid multibase prefix, but nonsense key bytes
    let bad = "z11111111111111111111111111111111";

    let err = validate_verification_method_multikey(Algorithm::X25519, "Multikey", bad);

    assert!(err.is_err());
}
