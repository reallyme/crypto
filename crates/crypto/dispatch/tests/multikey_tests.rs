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
    feature = "ml-kem-1024",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "x25519"
))]

use crypto_core::Algorithm;
use crypto_dispatch::{generate_keypair, public_key_to_multikey};

#[test]
fn ed25519_multikey_encoding_is_correct() {
    let (public, _) = generate_keypair(Algorithm::Ed25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::Ed25519, &public).unwrap();

    assert!(mk.starts_with("z"));
    assert!(mk.len() > 10);
}

#[test]
fn x25519_multikey_encoding_is_correct() {
    let (public, _) = generate_keypair(Algorithm::X25519).unwrap();
    let mk = public_key_to_multikey(Algorithm::X25519, &public).unwrap();

    assert!(mk.starts_with("z"));
    assert!(mk.len() > 10);
}

#[test]
fn ml_kem_multikey_encoding_is_correct() {
    let (public, _) = generate_keypair(Algorithm::MlKem1024).unwrap();
    let mk = public_key_to_multikey(Algorithm::MlKem1024, &public).unwrap();

    assert!(mk.starts_with("z"));
    assert!(mk.len() > 100); // large PQ key
}

#[test]
fn multikey_encoding_rejects_invalid_key_length() {
    let fake_key = vec![0u8; 10];

    let err = public_key_to_multikey(Algorithm::MlKem1024, &fake_key);
    assert!(err.is_err());
}

#[test]
fn p256_multikey_encoding_is_correct() {
    let (public, _) = generate_keypair(Algorithm::P256).unwrap();

    // Your keygen returns compressed SEC1
    assert_eq!(public.len(), 33);
    assert!(public[0] == 0x02 || public[0] == 0x03);

    let mk = public_key_to_multikey(Algorithm::P256, &public).unwrap();
    assert!(mk.starts_with("z"));
    assert!(mk.len() > 10);
}

#[test]
fn p384_multikey_encoding_is_correct() {
    let (public, _) = generate_keypair(Algorithm::P384).unwrap();
    assert_eq!(public.len(), 49);
    assert!(public[0] == 0x02 || public[0] == 0x03);

    let mk = public_key_to_multikey(Algorithm::P384, &public).unwrap();
    assert!(mk.starts_with("z"));
    assert!(mk.len() > 10);
}

#[test]
fn p521_multikey_encoding_is_correct() {
    let (public, _) = generate_keypair(Algorithm::P521).unwrap();
    assert_eq!(public.len(), 67);
    assert!(public[0] == 0x02 || public[0] == 0x03);

    let mk = public_key_to_multikey(Algorithm::P521, &public).unwrap();
    assert!(mk.starts_with("z"));
    assert!(mk.len() > 10);
}
