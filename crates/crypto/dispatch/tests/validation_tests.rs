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
#![cfg(all(
    feature = "native",
    feature = "ed25519",
    feature = "ml-kem-1024",
    feature = "x25519"
))]

use codec_multikey::encode_multikey;
use crypto_core::Algorithm;
use crypto_dispatch::{
    generate_keypair, public_key_to_multikey, validate_verification_method_multikey, AlgorithmError,
};

#[test]
fn x25519_verification_method_is_valid() {
    let (public, _) = generate_keypair(Algorithm::X25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::X25519, &public).unwrap();

    validate_verification_method_multikey(Algorithm::X25519, "Multikey", &mk)
        .expect("valid X25519 multikey");
}

#[test]
fn x25519_verification_method_rejects_masked_high_bit_alias() {
    let (mut public, _) = generate_keypair(Algorithm::X25519).unwrap();
    public[31] |= 0x80;
    assert!(matches!(
        public_key_to_multikey(Algorithm::X25519, &public),
        Err(AlgorithmError::InvalidKey(Algorithm::X25519))
    ));

    let alias = encode_multikey("x25519-pub", &public).unwrap();
    assert!(matches!(
        validate_verification_method_multikey(Algorithm::X25519, "Multikey", &alias),
        Err(AlgorithmError::InvalidKey(Algorithm::X25519))
    ));
}

#[test]
fn x25519_verification_method_rejects_noncanonical_field_aliases() {
    let mut field_boundary = [0xff_u8; 32];
    field_boundary[31] = 0x7f;
    field_boundary[0] = 0xec;
    assert!(public_key_to_multikey(Algorithm::X25519, &field_boundary).is_ok());

    for low_byte in 0xed..=0xff {
        field_boundary[0] = low_byte;
        assert!(matches!(
            public_key_to_multikey(Algorithm::X25519, &field_boundary),
            Err(AlgorithmError::InvalidKey(Algorithm::X25519))
        ));
        let alias = encode_multikey("x25519-pub", &field_boundary).unwrap();
        assert!(matches!(
            validate_verification_method_multikey(Algorithm::X25519, "Multikey", &alias),
            Err(AlgorithmError::InvalidKey(Algorithm::X25519))
        ));
    }
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
fn ed25519_verification_method_rejects_invalid_points() {
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let mut aliased_identity = [0xff_u8; 32];
    aliased_identity[0] = 0xee;
    aliased_identity[31] = 0x7f;
    for invalid in [identity, aliased_identity, [0_u8; 32]] {
        assert!(matches!(
            public_key_to_multikey(Algorithm::Ed25519, &invalid),
            Err(AlgorithmError::InvalidKey(Algorithm::Ed25519))
        ));
        let multikey = encode_multikey("ed25519-pub", &invalid).unwrap();
        assert!(matches!(
            validate_verification_method_multikey(Algorithm::Ed25519, "Multikey", &multikey),
            Err(AlgorithmError::InvalidKey(Algorithm::Ed25519))
        ));
    }
}

#[test]
fn invalid_multikey_string_is_rejected() {
    let bad = "zthisisnotvalidmultikeydata";

    let err = validate_verification_method_multikey(Algorithm::X25519, "Multikey", bad);

    assert!(matches!(
        err,
        Err(AlgorithmError::InvalidKey(Algorithm::X25519))
    ));
}

#[test]
fn wrong_algorithm_is_rejected() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    let err = validate_verification_method_multikey(Algorithm::X25519, "Multikey", &mk);

    assert!(matches!(
        err,
        Err(AlgorithmError::InvalidKey(Algorithm::X25519))
    ));
}

#[test]
fn wrong_binding_type_is_rejected() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    let err = validate_verification_method_multikey(Algorithm::Ed25519, "SomeOtherKeyType", &mk);

    assert!(matches!(
        err,
        Err(AlgorithmError::InvalidKey(Algorithm::Ed25519))
    ));
}

#[test]
fn wrong_key_length_is_rejected() {
    // valid multibase prefix, but nonsense key bytes
    let bad = "z11111111111111111111111111111111";

    let err = validate_verification_method_multikey(Algorithm::X25519, "Multikey", bad);

    assert!(matches!(
        err,
        Err(AlgorithmError::InvalidKey(Algorithm::X25519))
    ));
}
