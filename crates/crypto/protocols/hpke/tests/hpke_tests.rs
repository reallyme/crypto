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

use crypto_hpke::{open_base, seal_base, HpkeError, HpkeOpenRequest, HpkeSealRequest, HpkeSuite};

const P256_PRIVATE_KEY: [u8; 32] = [
    0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf, 0xee,
    0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91, 0xc3, 0x44,
];
const P256_PUBLIC_KEY_UNCOMPRESSED: [u8; 65] = [
    0x04, 0x07, 0xfc, 0xcb, 0x43, 0x45, 0x09, 0x6f, 0x96, 0x21, 0x72, 0x6f, 0xc4, 0xe4, 0x37, 0xbe,
    0x0c, 0xf8, 0x1c, 0x43, 0x10, 0x81, 0xf3, 0x28, 0xe5, 0x54, 0x96, 0x72, 0x39, 0xac, 0x55, 0x22,
    0xee, 0x0d, 0x97, 0x14, 0x75, 0x3e, 0xc6, 0xf7, 0x7f, 0x55, 0x7a, 0xa7, 0x37, 0x14, 0x26, 0x9d,
    0x5a, 0xcf, 0xeb, 0x72, 0x94, 0xbe, 0xbd, 0xcf, 0xfc, 0x67, 0xc1, 0x5a, 0x65, 0x11, 0x15, 0x5f,
    0x80,
];
const X25519_PRIVATE_KEY: [u8; 32] = [
    0x13, 0xb4, 0x0e, 0x43, 0x43, 0x29, 0xc8, 0x39, 0x59, 0x22, 0xa6, 0x6d, 0x6f, 0xb8, 0xc5, 0x0d,
    0x3b, 0x35, 0x26, 0x3f, 0x8e, 0x5c, 0x06, 0xca, 0xc6, 0x24, 0xa8, 0x65, 0x27, 0xd3, 0xb3, 0x04,
];
const X25519_PUBLIC_KEY: [u8; 32] = [
    0xcb, 0xbe, 0xc1, 0xce, 0x67, 0x44, 0x00, 0x87, 0xd0, 0x3b, 0xfd, 0x85, 0x36, 0xea, 0x3f, 0x7f,
    0xa9, 0x22, 0xcf, 0x52, 0x9a, 0xbc, 0x66, 0x57, 0x8b, 0x62, 0xf3, 0xbf, 0x5a, 0xb2, 0x61, 0x41,
];

#[test]
fn p256_base_mode_roundtrip() {
    assert_hpke_roundtrip(
        HpkeSuite::P256Sha256Aes256Gcm,
        &P256_PUBLIC_KEY_UNCOMPRESSED,
        &P256_PRIVATE_KEY,
    );
}

#[test]
fn x25519_base_mode_roundtrip() {
    assert_hpke_roundtrip(
        HpkeSuite::X25519Sha256ChaCha20Poly1305,
        &X25519_PUBLIC_KEY,
        &X25519_PRIVATE_KEY,
    );
}

#[test]
fn invalid_public_key_length_is_rejected() {
    let err = match seal_base(&HpkeSealRequest {
        suite: HpkeSuite::P256Sha256Aes256Gcm,
        recipient_public_key: &P256_PUBLIC_KEY_UNCOMPRESSED[..64],
        info: b"info",
        aad: b"aad",
        plaintext: b"plaintext",
    }) {
        Err(err) => err,
        Ok(_) => panic!("invalid public-key length must fail"),
    };

    assert_eq!(err, HpkeError::InvalidPublicKey);
}

#[test]
fn invalid_private_key_length_is_rejected() {
    let sealed = seal_base(&HpkeSealRequest {
        suite: HpkeSuite::P256Sha256Aes256Gcm,
        recipient_public_key: &P256_PUBLIC_KEY_UNCOMPRESSED,
        info: b"info",
        aad: b"aad",
        plaintext: b"plaintext",
    })
    .expect("sealing must succeed");

    let err = match open_base(&HpkeOpenRequest {
        suite: HpkeSuite::P256Sha256Aes256Gcm,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: &P256_PRIVATE_KEY[..31],
        info: b"info",
        aad: b"aad",
        ciphertext: &sealed.ciphertext,
    }) {
        Err(err) => err,
        Ok(_) => panic!("invalid private-key length must fail"),
    };

    assert_eq!(err, HpkeError::InvalidPrivateKey);
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let sealed = seal_base(&HpkeSealRequest {
        suite: HpkeSuite::P256Sha256Aes256Gcm,
        recipient_public_key: &P256_PUBLIC_KEY_UNCOMPRESSED,
        info: b"info",
        aad: b"aad",
        plaintext: b"plaintext",
    })
    .expect("sealing must succeed");
    let mut tampered = sealed.ciphertext;
    tampered[0] ^= 0x80;

    let err = match open_base(&HpkeOpenRequest {
        suite: HpkeSuite::P256Sha256Aes256Gcm,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: &P256_PRIVATE_KEY,
        info: b"info",
        aad: b"aad",
        ciphertext: &tampered,
    }) {
        Err(err) => err,
        Ok(_) => panic!("tampered ciphertext must fail"),
    };

    assert_eq!(err, HpkeError::OpenFailed);
}

fn assert_hpke_roundtrip(suite: HpkeSuite, public_key: &[u8], private_key: &[u8]) {
    let plaintext = b"ReallyMe HPKE Base mode test payload";
    let sealed = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: public_key,
        info: b"reallyme-hpke-info",
        aad: b"reallyme-hpke-aad",
        plaintext,
    })
    .expect("sealing must succeed");

    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: private_key,
        info: b"reallyme-hpke-info",
        aad: b"reallyme-hpke-aad",
        ciphertext: &sealed.ciphertext,
    })
    .expect("opening must succeed");

    assert_eq!(opened.plaintext.as_slice(), plaintext);
}
