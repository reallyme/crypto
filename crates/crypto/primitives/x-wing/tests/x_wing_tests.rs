// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X-Wing suite tests.

#![allow(clippy::expect_used)]

use crypto_x_wing::{
    generate_x_wing_1024_keypair, generate_x_wing_1024_keypair_derand, generate_x_wing_768_keypair,
    generate_x_wing_768_keypair_derand, x_wing_1024_decapsulate, x_wing_1024_encapsulate,
    x_wing_1024_encapsulate_derand, x_wing_768_decapsulate, x_wing_768_encapsulate,
    x_wing_768_encapsulate_derand, X_WING_1024_CIPHERTEXT_LEN, X_WING_1024_PUBLIC_KEY_LEN,
    X_WING_768_CIPHERTEXT_LEN, X_WING_768_PUBLIC_KEY_LEN, X_WING_ENCAPS_SEED_LEN,
    X_WING_SECRET_KEY_LEN, X_WING_SHARED_SECRET_LEN,
};

const SECRET_SEED: [u8; X_WING_SECRET_KEY_LEN] = [
    0x58, 0x12, 0xa3, 0x0d, 0x9b, 0x71, 0x44, 0x06, 0xc2, 0x83, 0x5f, 0xbe, 0x9d, 0x40, 0x2a, 0x77,
    0x31, 0xca, 0x8e, 0x19, 0xd6, 0x52, 0x90, 0xa4, 0x0f, 0xb5, 0xc8, 0x66, 0xe1, 0x23, 0x7a, 0x5d,
];
const ENCAPS_SEED: [u8; X_WING_ENCAPS_SEED_LEN] = [
    0x91, 0x02, 0x55, 0x1a, 0x83, 0xe4, 0x6c, 0x7f, 0x20, 0xbb, 0x39, 0xcd, 0x42, 0x5e, 0xa1, 0x08,
    0xd4, 0x67, 0x72, 0x9f, 0x33, 0x15, 0xfa, 0xe0, 0x6b, 0x88, 0xc1, 0x2d, 0x54, 0x9a, 0x0f, 0x7e,
    0x45, 0x12, 0xc6, 0xf0, 0x7d, 0x93, 0x2a, 0x5b, 0xe8, 0x01, 0x69, 0x34, 0xaf, 0xdc, 0x7b, 0x2e,
    0x19, 0x80, 0x4d, 0xa2, 0x56, 0xf1, 0x63, 0xb9, 0x0c, 0x3a, 0xde, 0x27, 0x74, 0x85, 0x9e, 0x11,
];
const X25519_COMPONENT_LEN: usize = 32;

#[test]
fn x_wing_768_derand_round_trips() {
    let (public_key, secret_key) =
        generate_x_wing_768_keypair_derand(&SECRET_SEED).expect("derandomized X-Wing-768 keypair");
    assert_eq!(public_key.len(), X_WING_768_PUBLIC_KEY_LEN);
    assert_eq!(secret_key.len(), X_WING_SECRET_KEY_LEN);

    let (ciphertext, encapsulated) =
        x_wing_768_encapsulate_derand(&public_key, &ENCAPS_SEED).expect("X-Wing-768 encapsulate");
    assert_eq!(ciphertext.len(), X_WING_768_CIPHERTEXT_LEN);
    assert_eq!(encapsulated.len(), X_WING_SHARED_SECRET_LEN);

    let decapsulated =
        x_wing_768_decapsulate(&ciphertext, &secret_key).expect("X-Wing-768 decapsulate");
    assert_eq!(encapsulated.as_slice(), decapsulated.as_slice());
}

#[test]
fn x_wing_1024_derand_round_trips() {
    let (public_key, secret_key) = generate_x_wing_1024_keypair_derand(&SECRET_SEED)
        .expect("derandomized X-Wing-1024 keypair");
    assert_eq!(public_key.len(), X_WING_1024_PUBLIC_KEY_LEN);
    assert_eq!(secret_key.len(), X_WING_SECRET_KEY_LEN);

    let (ciphertext, encapsulated) =
        x_wing_1024_encapsulate_derand(&public_key, &ENCAPS_SEED).expect("X-Wing-1024 encapsulate");
    assert_eq!(ciphertext.len(), X_WING_1024_CIPHERTEXT_LEN);
    assert_eq!(encapsulated.len(), X_WING_SHARED_SECRET_LEN);

    let decapsulated =
        x_wing_1024_decapsulate(&ciphertext, &secret_key).expect("X-Wing-1024 decapsulate");
    assert_eq!(encapsulated.as_slice(), decapsulated.as_slice());
}

#[test]
fn randomized_keygen_and_encapsulation_round_trip() {
    let (public_key, secret_key) =
        generate_x_wing_768_keypair().expect("randomized X-Wing-768 keypair");
    let (ciphertext, encapsulated) =
        x_wing_768_encapsulate(&public_key).expect("randomized X-Wing-768 encapsulate");
    let decapsulated =
        x_wing_768_decapsulate(&ciphertext, &secret_key).expect("X-Wing-768 decapsulate");
    assert_eq!(encapsulated.as_slice(), decapsulated.as_slice());

    let (public_key, secret_key) =
        generate_x_wing_1024_keypair().expect("randomized X-Wing-1024 keypair");
    let (ciphertext, encapsulated) =
        x_wing_1024_encapsulate(&public_key).expect("randomized X-Wing-1024 encapsulate");
    let decapsulated =
        x_wing_1024_decapsulate(&ciphertext, &secret_key).expect("X-Wing-1024 decapsulate");
    assert_eq!(encapsulated.as_slice(), decapsulated.as_slice());
}

#[test]
fn invalid_lengths_are_rejected() {
    assert!(generate_x_wing_768_keypair_derand(&SECRET_SEED[..31]).is_err());
    assert!(x_wing_768_encapsulate_derand(&[], &ENCAPS_SEED).is_err());
    let (public_key, secret_key) =
        generate_x_wing_768_keypair_derand(&SECRET_SEED).expect("derandomized X-Wing-768 keypair");
    assert!(x_wing_768_encapsulate_derand(&public_key, &ENCAPS_SEED[..63]).is_err());
    assert!(x_wing_768_decapsulate(&[], &secret_key).is_err());
}

#[test]
fn decapsulation_accepts_low_order_x25519_component_per_x_wing_spec() {
    let (public_key, secret_key) =
        generate_x_wing_768_keypair_derand(&SECRET_SEED).expect("derandomized X-Wing-768 keypair");
    let (mut ciphertext, shared_secret) =
        x_wing_768_encapsulate_derand(&public_key, &ENCAPS_SEED).expect("X-Wing-768 encapsulate");
    let start = ciphertext
        .len()
        .checked_sub(X25519_COMPONENT_LEN)
        .expect("ciphertext length covers X25519 component");
    ciphertext[start..].fill(0);
    let decapsulated =
        x_wing_768_decapsulate(&ciphertext, &secret_key).expect("X-Wing decapsulates per spec");
    assert_eq!(decapsulated.len(), X_WING_SHARED_SECRET_LEN);
    assert_ne!(decapsulated.as_slice(), shared_secret.as_slice());
}
