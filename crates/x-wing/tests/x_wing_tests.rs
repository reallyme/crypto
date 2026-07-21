// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X-Wing suite tests.

#![allow(clippy::expect_used)]

use crypto_x_wing::{
    generate_x_wing_768_keypair, generate_x_wing_768_keypair_derand, x_wing_768_decapsulate,
    x_wing_768_encapsulate, x_wing_768_encapsulate_derand, X_WING_768_CIPHERTEXT_LEN,
    X_WING_768_PUBLIC_KEY_LEN, X_WING_ENCAPS_SEED_LEN, X_WING_SECRET_KEY_LEN,
    X_WING_SHARED_SECRET_LEN,
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
const X25519_ORDER_EIGHT_POINT: [u8; X25519_COMPONENT_LEN] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];
const LOW_ORDER_EXPECTED_SHARED_SECRETS: [[u8; X_WING_SHARED_SECRET_LEN]; 2] = [
    [
        0xa2, 0x93, 0xa5, 0xfb, 0xf5, 0xb7, 0xc2, 0x77, 0x82, 0xab, 0x8d, 0xfa, 0xd8, 0xc0, 0x5a,
        0xc6, 0xaa, 0xb9, 0xd9, 0x60, 0xd2, 0xb8, 0xc3, 0xdb, 0xe2, 0x88, 0x7f, 0x6e, 0x19, 0x11,
        0xeb, 0x0d,
    ],
    [
        0xdb, 0xbd, 0xa7, 0x0c, 0x3a, 0x15, 0xff, 0xdd, 0xf2, 0x13, 0xd8, 0xab, 0xd9, 0x18, 0xc3,
        0x0f, 0xff, 0xf6, 0x02, 0xd6, 0x7f, 0xd6, 0x7e, 0x65, 0xa0, 0x1b, 0xf0, 0x40, 0x4b, 0xf0,
        0x5a, 0x78,
    ],
];

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
fn randomized_keygen_and_encapsulation_round_trip() {
    let (public_key, secret_key) =
        generate_x_wing_768_keypair().expect("randomized X-Wing-768 keypair");
    let (ciphertext, encapsulated) =
        x_wing_768_encapsulate(&public_key).expect("randomized X-Wing-768 encapsulate");
    let decapsulated =
        x_wing_768_decapsulate(&ciphertext, &secret_key).expect("X-Wing-768 decapsulate");
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
fn decapsulation_accepts_low_order_x25519_components_per_x_wing_spec() {
    let (public_key, secret_key) =
        generate_x_wing_768_keypair_derand(&SECRET_SEED).expect("derandomized X-Wing-768 keypair");
    let (ciphertext, shared_secret) =
        x_wing_768_encapsulate_derand(&public_key, &ENCAPS_SEED).expect("X-Wing-768 encapsulate");
    for (index, low_order_point) in [[0_u8; X25519_COMPONENT_LEN], X25519_ORDER_EIGHT_POINT]
        .iter()
        .enumerate()
    {
        let mut adversarial_ciphertext = ciphertext.clone();
        let start = adversarial_ciphertext
            .len()
            .checked_sub(X25519_COMPONENT_LEN)
            .expect("ciphertext length covers X25519 component");
        adversarial_ciphertext[start..].copy_from_slice(low_order_point);
        let decapsulated = x_wing_768_decapsulate(&adversarial_ciphertext, &secret_key)
            .expect("X-Wing decapsulates per spec");
        assert_eq!(decapsulated.len(), X_WING_SHARED_SECRET_LEN);
        assert_eq!(
            decapsulated.as_slice(),
            LOW_ORDER_EXPECTED_SHARED_SECRETS[index].as_slice()
        );
        assert_ne!(decapsulated.as_slice(), shared_secret.as_slice());
    }
}
